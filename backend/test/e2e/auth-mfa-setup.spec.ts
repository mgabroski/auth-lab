/**
 * test/e2e/auth-mfa-setup.spec.ts
 *
 * E2E tests for POST /auth/mfa/setup and /auth/mfa/verify-setup (Brick 9a).
 * Covers provisional secret + QR generation and the setup verification flow.
 */

import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';

import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';
import type { MembershipRole } from '../../src/modules/memberships/membership.types';

function parseJson<T>(res: LightMyRequestResponse): T {
  const body = Buffer.isBuffer(res.body) ? res.body.toString('utf8') : res.body;
  return JSON.parse(body) as T;
}

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
  role: MembershipRole;
}): Promise<{ id: string }> {
  const user = await opts.db
    .insertInto('users')
    .values({ email: opts.email.toLowerCase(), name: 'Test User' })
    .returning(['id'])
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

  return { id: user.id };
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

  expect(res.statusCode).toBe(200);

  const setCookie = res.headers['set-cookie'];
  expect(setCookie).toBeTruthy();

  if (Array.isArray(setCookie)) return setCookie[0];
  return setCookie as string;
}

describe('POST /auth/mfa/setup + /auth/mfa/verify-setup', () => {
  it('requires authentication (no cookie)', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;

    try {
      await createTenant({ db: deps.db, tenantKey });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { host: `${tenantKey}.hubins.com` },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('returns secret + qrCodeUri + recoveryCodes for authenticated user', async () => {
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

      const body = parseJson<{ secret: string; qrCodeUri: string; recoveryCodes: string[] }>(res);
      expect(body.secret).toBeTruthy();
      expect(body.qrCodeUri).toBeTruthy();
      expect(body.recoveryCodes.length).toBeGreaterThan(0);
    } finally {
      await app.close();
    }
  });

  it('verify-setup rejects invalid TOTP code', async () => {
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

  it('verify-setup accepts valid TOTP code and marks session MFA verified', async () => {
    const { app, deps, cryptoHelpers } = await buildTestApp();
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

      const setupRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      const setupBody = parseJson<{ secret: string }>(setupRes);
      const validCode = cryptoHelpers.generateTotpCode(setupBody.secret);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: validCode },
      });

      expect(res.statusCode).toBe(200);

      const body = parseJson<{ status: string; nextAction: string }>(res);
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE');
    } finally {
      await app.close();
    }
  });

  it('writes auth.mfa.setup.completed audit event on success', async () => {
    const { app, deps, cryptoHelpers } = await buildTestApp();
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

      const setupBody = parseJson<{ secret: string }>(setupRes);
      const validCode = cryptoHelpers.generateTotpCode(setupBody.secret);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: validCode },
      });

      expect(res.statusCode).toBe(200);

      const body = parseJson<{ status: string; nextAction: string }>(res);
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
