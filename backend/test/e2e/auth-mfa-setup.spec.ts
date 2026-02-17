/**
 * test/e2e/auth-mfa-setup.spec.ts
 *
 * E2E tests for POST /auth/mfa/setup and POST /auth/mfa/verify-setup (Brick 9a).
 *
 * Isolation: UUID-suffixed emails and tenant keys.
 * All audit assertions are scoped by user_id (never full-table counts).
 *
 * NOTE:
 * - Recovery codes count is config-driven (AppConfig.mfa.recoveryCodesCount).
 * - Default in config.ts is 10, so tests assert 10 unless overridden.
 */

import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import type { FastifyInstance } from 'fastify';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';

// ── Shared helpers ───────────────────────────────────────────────────────────

async function createTenant(opts: { db: DbExecutor; tenantKey: string }) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: false,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

async function seedUserWithPassword(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  tenantId: string;
  email: string;
  password: string;
  role: 'ADMIN' | 'MEMBER';
}) {
  const user = await opts.db
    .insertInto('users')
    .values({ email: opts.email.toLowerCase(), name: 'Test User' })
    .returning(['id', 'email'])
    .executeTakeFirstOrThrow();

  const passwordHash = await opts.passwordHasher.hash(opts.password);
  await opts.db
    .insertInto('auth_identities')
    .values({
      user_id: user.id,
      provider: 'password',
      password_hash: passwordHash,
      provider_subject: null,
    })
    .execute();

  await opts.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: opts.role,
      status: 'ACTIVE',
    })
    .execute();

  return user;
}

async function loginAndGetCookie(opts: {
  app: FastifyInstance;
  tenantKey: string;
  email: string;
  password: string;
}): Promise<string> {
  const res = await opts.app.inject({
    method: 'POST',
    url: '/auth/login',
    headers: { host: `${opts.tenantKey}.hubins.com` },
    body: { email: opts.email, password: opts.password },
  });

  const setCookie = res.headers['set-cookie'];
  const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;

  if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) {
    throw new Error('Expected set-cookie header');
  }

  return cookieHeader.split(';')[0]; // "sid=<value>"
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('POST /auth/mfa/setup', () => {
  it('returns secret + qrCodeUri + recovery codes (default 10) of 16 chars each', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'ADMIN',
      });

      const cookie = await loginAndGetCookie({ app, tenantKey, email, password });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);

      const body = res.json<{ secret: string; qrCodeUri: string; recoveryCodes: string[] }>();

      expect(typeof body.secret).toBe('string');
      expect(body.secret.length).toBeGreaterThan(0);

      expect(typeof body.qrCodeUri).toBe('string');
      expect(body.qrCodeUri).toContain('otpauth://totp/');

      expect(Array.isArray(body.recoveryCodes)).toBe(true);

      // Default in config.ts is 10 unless overridden
      expect(body.recoveryCodes).toHaveLength(10);

      for (const code of body.recoveryCodes) {
        expect(typeof code).toBe('string');
        expect(code.length).toBe(16);
      }
    } finally {
      await app.close();
    }
  });

  it('returns 401 when no session present', async () => {
    const { app } = await buildTestApp();
    try {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { host: 'any-tenant.hubins.com' },
      });
      expect(res.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('returns 409 when MFA is already configured', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const user = await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'ADMIN',
      });

      await deps.db
        .insertInto('mfa_secrets')
        .values({
          user_id: user.id,
          encrypted_secret: 'fake-encrypted-secret',
          is_verified: true,
        })
        .execute();

      const cookie = await loginAndGetCookie({ app, tenantKey, email, password });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(409);
      const body = res.json<{ error: { message: string } }>();
      expect(body.error.message.toLowerCase()).toContain('already configured');
    } finally {
      await app.close();
    }
  });

  it('writes auth.mfa.setup.started audit event scoped to user', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const user = await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'ADMIN',
      });

      const cookie = await loginAndGetCookie({ app, tenantKey, email, password });

      await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      const auditRow = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.mfa.setup.started')
        .where('user_id', '=', user.id)
        .executeTakeFirst();

      expect(auditRow).toBeDefined();
    } finally {
      await app.close();
    }
  });
});

describe('POST /auth/mfa/verify-setup', () => {
  it('returns 409 when no unverified secret exists', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'ADMIN',
      });

      const cookie = await loginAndGetCookie({ app, tenantKey, email, password });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: '123456' },
      });

      expect(res.statusCode).toBe(409);
      const body = res.json<{ error: { message: string } }>();
      expect(body.error.message).toContain('No MFA setup in progress');
    } finally {
      await app.close();
    }
  });

  it('returns 401 on wrong code', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'ADMIN',
      });

      const cookie = await loginAndGetCookie({ app, tenantKey, email, password });

      await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: '000000' },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('writes auth.mfa.setup.completed audit event on success', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const user = await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'ADMIN',
      });

      const cookie = await loginAndGetCookie({ app, tenantKey, email, password });

      const setupRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      const { secret } = setupRes.json<{ secret: string }>();

      // TEST helper lives on AuthService
      const validCode = deps.auth.authService.generateTotpCodeForTest(secret);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: validCode },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ status: string; nextAction: string }>();
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE');

      const auditRow = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.mfa.setup.completed')
        .where('user_id', '=', user.id)
        .executeTakeFirst();

      expect(auditRow).toBeDefined();
    } finally {
      await app.close();
    }
  });
});
