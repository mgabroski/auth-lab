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
}): Promise<{ userId: string; membershipId: string }> {
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

  const membership = await opts.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: 'ADMIN',
      status: 'ACTIVE',
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  await opts.db
    .insertInto('mfa_secrets')
    .values({
      user_id: user.id,
      encrypted_secret: opts.mfaSecretEncrypted,
      is_verified: true,
    })
    .execute();

  return { userId: user.id, membershipId: membership.id };
}

describe('POST /auth/mfa/verify', () => {
  it('admin login returns MFA_REQUIRED in nextAction (regression check)', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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
      const preMfaCookie = Array.isArray(cookie) ? cookie[0] : (cookie as string);

      const validCode = cryptoHelpers.generateTotpCode(plainSecret);

      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: {
          host: `${tenantKey}.hubins.com`,
          cookie: preMfaCookie,
        },
        body: { code: validCode },
      });

      expect(verifyRes.statusCode).toBe(200);
      const body = parseJson<{ status: string; nextAction: string }>(verifyRes);
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE');

      const postCookie = verifyRes.headers['set-cookie'];
      expect(postCookie).toBeTruthy();
      const postMfaCookie = Array.isArray(postCookie) ? postCookie[0] : (postCookie as string);
      expect(postMfaCookie).not.toEqual(preMfaCookie);

      const usingOld = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie: preMfaCookie },
        body: { code: validCode },
      });
      expect(usingOld.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('replay protection: same TOTP code used twice (different sessions) → second is 401', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = cryptoHelpers.generateTotpSecret();
      const encryptedSecret = cryptoHelpers.encryptSecret(plainSecret);

      const seeded = await seedAdminWithMfa({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
      });

      const sessionIdA = await deps.sessionStore.create({
        userId: seeded.userId,
        tenantId: tenant.id,
        tenantKey,
        membershipId: seeded.membershipId,
        role: 'ADMIN',
        emailVerified: true,
        mfaVerified: false,
        createdAt: new Date().toISOString(),
      });
      const sessionCookieA = `sid=${sessionIdA}`;

      const sessionIdB = await deps.sessionStore.create({
        userId: seeded.userId,
        tenantId: tenant.id,
        tenantKey,
        membershipId: seeded.membershipId,
        role: 'ADMIN',
        emailVerified: true,
        mfaVerified: false,
        createdAt: new Date().toISOString(),
      });
      const sessionCookieB = `sid=${sessionIdB}`;

      const validCode = cryptoHelpers.generateTotpCode(plainSecret);

      const first = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie: sessionCookieA },
        body: { code: validCode },
      });
      expect(first.statusCode).toBe(200);

      const second = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie: sessionCookieB },
        body: { code: validCode },
      });
      expect(second.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('fail-open on replay cache READ error: valid code still succeeds', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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
      const cookieHeader = loginRes.headers['set-cookie'];
      expect(cookieHeader).toBeTruthy();
      const preMfaCookie = Array.isArray(cookieHeader) ? cookieHeader[0] : (cookieHeader as string);

      const originalGet = deps.cache.get.bind(deps.cache);
      deps.cache.get = async (key: string) => {
        if (key.startsWith('totp:used:')) throw new Error('redis_read_error');
        return originalGet(key);
      };

      const validCode = cryptoHelpers.generateTotpCode(plainSecret);
      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie: preMfaCookie },
        body: { code: validCode },
      });
      expect(res.statusCode).toBe(200);
    } finally {
      await app.close();
    }
  });

  it('fail-open on replay cache WRITE error: valid code still succeeds', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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
      const cookieHeader = loginRes.headers['set-cookie'];
      expect(cookieHeader).toBeTruthy();
      const preMfaCookie = Array.isArray(cookieHeader) ? cookieHeader[0] : (cookieHeader as string);

      const originalSetIfAbsent = deps.cache.setIfAbsent.bind(deps.cache);
      deps.cache.setIfAbsent = async (
        key: string,
        value: string,
        opts?: { ttlSeconds?: number },
      ) => {
        if (key.startsWith('totp:used:')) throw new Error('redis_write_error');
        return originalSetIfAbsent(key, value, opts);
      };

      const validCode = cryptoHelpers.generateTotpCode(plainSecret);
      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie: preMfaCookie },
        body: { code: validCode },
      });
      expect(res.statusCode).toBe(200);
    } finally {
      await app.close();
    }
  });

  it('wrong code → 401', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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
      const preMfaCookie = Array.isArray(cookie) ? cookie[0] : (cookie as string);

      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: {
          host: `${tenantKey}.hubins.com`,
          cookie: preMfaCookie,
        },
        body: { code: '000000' },
      });

      expect(verifyRes.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('mfaVerified already true -> 403 (cannot verify again on an already-verified session)', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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
      const preMfaCookie = Array.isArray(cookie) ? cookie[0] : (cookie as string);

      const validCode = cryptoHelpers.generateTotpCode(plainSecret);

      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: {
          host: `${tenantKey}.hubins.com`,
          cookie: preMfaCookie,
        },
        body: { code: validCode },
      });

      expect(verifyRes.statusCode).toBe(200);
      const postCookie = verifyRes.headers['set-cookie'];
      expect(postCookie).toBeTruthy();
      const postMfaCookie = Array.isArray(postCookie) ? postCookie[0] : (postCookie as string);

      const again = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host: `${tenantKey}.hubins.com`, cookie: postMfaCookie },
        body: { code: validCode },
      });
      expect(again.statusCode).toBe(403);
    } finally {
      await app.close();
    }
  });
});
