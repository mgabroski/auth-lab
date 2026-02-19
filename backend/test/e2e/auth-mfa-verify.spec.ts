/**
 * test/e2e/auth-mfa-verify.spec.ts
 *
 * E2E tests for POST /auth/mfa/verify (Brick 9b).
 * Covers post-login TOTP verification for admin users.
 */

import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import type { LightMyRequestResponse } from 'fastify';

import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';

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
    const { app, deps, cryptoHelpers } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = cryptoHelpers.generateTotpSecret();
      const encryptedSecret = cryptoHelpers.encryptSecret(plainSecret);

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
      const body = parseJson<{ nextAction: string }>(loginRes);
      expect(body.nextAction).toBe('MFA_REQUIRED');
    } finally {
      await app.close();
    }
  });

  it('correct TOTP code → 200 + nextAction: NONE', async () => {
    const { app, deps, cryptoHelpers } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = cryptoHelpers.generateTotpSecret();
      const encryptedSecret = cryptoHelpers.encryptSecret(plainSecret);

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
      const cookie = loginRes.headers['set-cookie'];
      expect(cookie).toBeTruthy();

      const validCode = cryptoHelpers.generateTotpCode(plainSecret);

      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: {
          host: `${tenantKey}.hubins.com`,
          cookie: Array.isArray(cookie) ? cookie[0] : (cookie as string),
        },
        body: { code: validCode },
      });

      expect(verifyRes.statusCode).toBe(200);
      const body = parseJson<{ status: string; nextAction: string }>(verifyRes);
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE');
    } finally {
      await app.close();
    }
  });

  it('wrong code → 401', async () => {
    const { app, deps, cryptoHelpers } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = cryptoHelpers.generateTotpSecret();
      const encryptedSecret = cryptoHelpers.encryptSecret(plainSecret);

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
      const cookie = loginRes.headers['set-cookie'];
      expect(cookie).toBeTruthy();

      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: {
          host: `${tenantKey}.hubins.com`,
          cookie: Array.isArray(cookie) ? cookie[0] : (cookie as string),
        },
        body: { code: '000000' },
      });

      expect(verifyRes.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('mfaVerified already true -> 403 (cannot verify again on an already-verified session)', async () => {
    const { app, deps, cryptoHelpers } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = cryptoHelpers.generateTotpSecret();
      const encryptedSecret = cryptoHelpers.encryptSecret(plainSecret);

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
      const cookie = loginRes.headers['set-cookie'];
      expect(cookie).toBeTruthy();
      const cookieHeader = Array.isArray(cookie) ? cookie[0] : (cookie as string);

      const validCode = cryptoHelpers.generateTotpCode(plainSecret);

      const first = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie: cookieHeader },
        body: { code: validCode },
      });
      expect(first.statusCode).toBe(200);

      const second = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie: cookieHeader },
        body: { code: validCode },
      });

      // LOCKED behavior: second attempt is forbidden, not idempotent success
      expect(second.statusCode).toBe(403);
    } finally {
      await app.close();
    }
  });
});
