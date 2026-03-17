/**
 * test/e2e/auth-mfa-recovery.spec.ts
 *
 * E2E tests for POST /auth/mfa/recover (Brick 9c).
 * Covers recovery-code based MFA verification for admin users.
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

async function seedAdminWithMfaAndRecovery(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  tenantId: string;
  email: string;
  password: string;
  mfaSecretEncrypted: string;
  recoveryCodeHash: string;
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

  await opts.db
    .insertInto('mfa_secrets')
    .values({
      user_id: user.id,
      encrypted_secret: opts.mfaSecretEncrypted,
      is_verified: true,
    })
    .execute();

  await opts.db
    .insertInto('mfa_recovery_codes')
    .values({
      user_id: user.id,
      code_hash: opts.recoveryCodeHash,
      used_at: null,
    })
    .execute();

  return { userId: user.id };
}

describe('POST /auth/mfa/recover', () => {
  it('successfully consumes recovery code and returns AUTHENTICATED', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';
    const recoveryCode = 'RecoveryCode123456';

    try {
      await reset();
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = cryptoHelpers.generateTotpSecret();
      const encryptedSecret = cryptoHelpers.encryptSecret(plainSecret);
      const codeHash = cryptoHelpers.hashRecoveryCode(recoveryCode);

      await seedAdminWithMfaAndRecovery({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
        recoveryCodeHash: codeHash,
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
      const preMfaCookie = Array.isArray(cookie) ? cookie[0] : (cookie as string);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: {
          host: `${tenantKey}.hubins.com`,
          cookie: preMfaCookie,
        },
        body: { recoveryCode },
      });

      expect(res.statusCode).toBe(200);
      const body = parseJson<{ status: string; nextAction: string }>(res);
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE');

      // LOCKED hardening: MFA recovery rotates session cookie.
      const postCookie = res.headers['set-cookie'];
      expect(postCookie).toBeTruthy();
      const postMfaCookie = Array.isArray(postCookie) ? postCookie[0] : (postCookie as string);
      expect(postMfaCookie).not.toEqual(preMfaCookie);

      const usingOld = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: { host: `${tenantKey}.hubins.com`, cookie: preMfaCookie },
        body: { recoveryCode },
      });
      expect(usingOld.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('consumed recovery code cannot be reused after a fresh login session', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';
    const recoveryCode = 'RecoveryCode123456';

    try {
      await reset();
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = cryptoHelpers.generateTotpSecret();
      const encryptedSecret = cryptoHelpers.encryptSecret(plainSecret);
      const codeHash = cryptoHelpers.hashRecoveryCode(recoveryCode);

      const seeded = await seedAdminWithMfaAndRecovery({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
        recoveryCodeHash: codeHash,
      });

      const firstLogin = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      expect(firstLogin.statusCode).toBe(200);
      const firstCookieHeader = firstLogin.headers['set-cookie'];
      expect(firstCookieHeader).toBeTruthy();
      const firstPreMfaCookie = Array.isArray(firstCookieHeader)
        ? firstCookieHeader[0]
        : (firstCookieHeader as string);

      const firstRecover = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: {
          host: `${tenantKey}.hubins.com`,
          cookie: firstPreMfaCookie,
        },
        body: { recoveryCode },
      });

      expect(firstRecover.statusCode).toBe(200);

      const storedCode = await deps.db
        .selectFrom('mfa_recovery_codes')
        .select(['used_at'])
        .where('user_id', '=', seeded.userId)
        .where('code_hash', '=', codeHash)
        .executeTakeFirstOrThrow();

      expect(storedCode.used_at).not.toBeNull();

      const secondLogin = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      expect(secondLogin.statusCode).toBe(200);
      const secondCookieHeader = secondLogin.headers['set-cookie'];
      expect(secondCookieHeader).toBeTruthy();
      const secondPreMfaCookie = Array.isArray(secondCookieHeader)
        ? secondCookieHeader[0]
        : (secondCookieHeader as string);

      const secondRecover = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: {
          host: `${tenantKey}.hubins.com`,
          cookie: secondPreMfaCookie,
        },
        body: { recoveryCode },
      });

      expect(secondRecover.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('rejects invalid recovery code', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';
    const recoveryCode = 'RecoveryCode123456';

    try {
      await reset();
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = cryptoHelpers.generateTotpSecret();
      const encryptedSecret = cryptoHelpers.encryptSecret(plainSecret);
      const codeHash = cryptoHelpers.hashRecoveryCode(recoveryCode);

      await seedAdminWithMfaAndRecovery({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
        recoveryCodeHash: codeHash,
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
      const preMfaCookie = Array.isArray(cookie) ? cookie[0] : (cookie as string);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: {
          host: `${tenantKey}.hubins.com`,
          cookie: preMfaCookie,
        },
        body: { recoveryCode: 'WrongCode1234567' },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('second call after successful recovery -> 403 (already MFA-verified session)', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';
    const recoveryCode = 'RecoveryCode123456';

    try {
      await reset();
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = cryptoHelpers.generateTotpSecret();
      const encryptedSecret = cryptoHelpers.encryptSecret(plainSecret);
      const codeHash = cryptoHelpers.hashRecoveryCode(recoveryCode);

      await seedAdminWithMfaAndRecovery({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
        recoveryCodeHash: codeHash,
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

      const first = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: { host: `${tenantKey}.hubins.com`, cookie: cookieHeader },
        body: { recoveryCode },
      });
      expect(first.statusCode).toBe(200);

      const firstSetCookie = first.headers['set-cookie'];
      expect(firstSetCookie).toBeTruthy();
      const rotatedCookie = Array.isArray(firstSetCookie)
        ? firstSetCookie[0]
        : (firstSetCookie as string);
      expect(rotatedCookie).not.toEqual(cookieHeader);

      const usingOld = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: { host: `${tenantKey}.hubins.com`, cookie: cookieHeader },
        body: { recoveryCode },
      });
      expect(usingOld.statusCode).toBe(401);

      const second = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: { host: `${tenantKey}.hubins.com`, cookie: rotatedCookie },
        body: { recoveryCode },
      });

      expect(second.statusCode).toBe(403);
    } finally {
      await app.close();
    }
  });
});
