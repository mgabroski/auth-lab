/**
 * test/e2e/auth-mfa-verify.spec.ts
 *
 * E2E tests for POST /auth/mfa/verify (Brick 9b).
 * Covers post-login TOTP verification for admin users.
 */

import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';

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

async function seedAdminWithMfa(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  tenantId: string;
  email: string;
  password: string;
  mfaSecretEncrypted: string;
}): Promise<{ userId: string }> {
  const user = await opts.db
    .insertInto('users')
    .values({ email: opts.email.toLowerCase(), name: 'Test Admin' })
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
      role: 'ADMIN',
      status: 'ACTIVE',
    })
    .execute();

  // Insert a VERIFIED MFA secret
  await opts.db
    .insertInto('mfa_secrets')
    .values({
      user_id: user.id,
      encrypted_secret: opts.mfaSecretEncrypted,
      is_verified: true,
    })
    .execute();

  return { userId: user.id };
}

describe('POST /auth/mfa/verify', () => {
  it('admin login returns MFA_REQUIRED in nextAction (regression check)', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = deps.auth.authService.generateTotpSecretForTest();
      const encryptedSecret = deps.auth.authService.encryptSecretForTest(plainSecret);

      await seedAdminWithMfa({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      expect(loginRes.statusCode).toBe(200);
      const body = loginRes.json<{ nextAction: string }>();
      expect(body.nextAction).toBe('MFA_REQUIRED');
    } finally {
      await app.close();
    }
  });

  it('correct TOTP code → 200 + nextAction: NONE', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = deps.auth.authService.generateTotpSecretForTest();
      const encryptedSecret = deps.auth.authService.encryptSecretForTest(plainSecret);

      await seedAdminWithMfa({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      const setCookie = loginRes.headers['set-cookie'];
      const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;
      if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) {
        throw new Error('Expected set-cookie header');
      }
      const cookie = cookieHeader.split(';')[0];

      const validCode = deps.auth.authService.generateTotpCodeForTest(plainSecret);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: validCode },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ status: string; nextAction: string }>();
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE');
    } finally {
      await app.close();
    }
  });

  it('wrong code → 401', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = deps.auth.authService.generateTotpSecretForTest();
      const encryptedSecret = deps.auth.authService.encryptSecretForTest(plainSecret);

      await seedAdminWithMfa({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      const setCookie = loginRes.headers['set-cookie'];
      const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;
      if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) {
        throw new Error('Expected set-cookie header');
      }
      const cookie = cookieHeader.split(';')[0];

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: '000000' },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('mfaVerified already true → 403', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `member-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      // Seed MEMBER (no MFA required) so login gives nextAction: NONE and session mfaVerified=true
      const user = await deps.db
        .insertInto('users')
        .values({ email: email.toLowerCase(), name: 'Member' })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const hash = await deps.passwordHasher.hash(password);

      await deps.db
        .insertInto('auth_identities')
        .values({
          user_id: user.id,
          provider: 'password',
          password_hash: hash,
          provider_subject: null,
        })
        .execute();

      await deps.db
        .insertInto('memberships')
        .values({ tenant_id: tenant.id, user_id: user.id, role: 'MEMBER', status: 'ACTIVE' })
        .execute();

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      const loginBody = loginRes.json<{ nextAction: string }>();
      expect(loginBody.nextAction).toBe('NONE');

      const setCookie = loginRes.headers['set-cookie'];
      const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;
      if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) {
        throw new Error('Expected set-cookie header');
      }
      const cookie = cookieHeader.split(';')[0];

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: '123456' },
      });

      expect(res.statusCode).toBe(403);
      const body = res.json<{ error: { message: string } }>();
      expect(body.error.message).toContain('already verified');
    } finally {
      await app.close();
    }
  });

  it('writes auth.mfa.verify.success and auth.mfa.verify.failed audit events', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = deps.auth.authService.generateTotpSecretForTest();
      const encryptedSecret = deps.auth.authService.encryptSecretForTest(plainSecret);

      const { userId } = await seedAdminWithMfa({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      const setCookie = loginRes.headers['set-cookie'];
      const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;
      if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) {
        throw new Error('Expected set-cookie header');
      }
      const cookie = cookieHeader.split(';')[0];

      // Failed attempt
      await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: '000000' },
      });

      const failAudit = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.mfa.verify.failed')
        .where('user_id', '=', userId)
        .executeTakeFirst();

      expect(failAudit).toBeDefined();

      // Successful attempt
      const validCode = deps.auth.authService.generateTotpCodeForTest(plainSecret);

      await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: validCode },
      });

      const successAudit = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.mfa.verify.success')
        .where('user_id', '=', userId)
        .executeTakeFirst();

      expect(successAudit).toBeDefined();
    } finally {
      await app.close();
    }
  });
});
