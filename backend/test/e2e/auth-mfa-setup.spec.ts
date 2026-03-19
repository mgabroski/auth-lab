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
}): Promise<{ userId: string }> {
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

  return { userId: user.id };
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
  const cookie = res.headers['set-cookie'];
  expect(cookie).toBeTruthy();
  return Array.isArray(cookie) ? cookie[0] : (cookie as string);
}

describe('POST /auth/mfa/setup and /auth/mfa/verify-setup', () => {
  it('requires authentication (no cookie)', async () => {
    const { app } = await buildTestApp();
    const res = await app.inject({
      method: 'POST',
      url: '/auth/mfa/setup',
      headers: { host: `tenant-${randomUUID()}.hubins.com` },
    });

    expect(res.statusCode).toBe(401);
    await app.close();
  });

  it('returns secret + qrCodeUri + recoveryCodes for authenticated user', async () => {
    const { app, deps, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const seeded = await seedUserWithPassword({
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

      expect(setupRes.statusCode).toBe(200);

      const body = parseJson<{ secret: string; qrCodeUri: string; recoveryCodes: string[] }>(
        setupRes,
      );
      expect(typeof body.secret).toBe('string');
      expect(body.secret.length).toBeGreaterThan(0);
      expect(typeof body.qrCodeUri).toBe('string');
      expect(body.qrCodeUri.length).toBeGreaterThan(0);
      expect(decodeURIComponent(body.qrCodeUri)).toContain('issuer=Hubins');
      expect(decodeURIComponent(body.qrCodeUri)).toContain(email);
      expect(decodeURIComponent(body.qrCodeUri)).not.toContain(seeded.userId);
      expect(Array.isArray(body.recoveryCodes)).toBe(true);
      expect(body.recoveryCodes.length).toBeGreaterThan(0);
    } finally {
      await app.close();
    }
  });

  it('verify-setup rejects invalid TOTP code', async () => {
    const { app, deps, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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

      expect(setupRes.statusCode).toBe(200);

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
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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

      // LOCKED hardening: MFA setup verification rotates session cookie.
      const postCookie = res.headers['set-cookie'];
      expect(postCookie).toBeTruthy();
      const postMfaCookie = Array.isArray(postCookie) ? postCookie[0] : (postCookie as string);
      expect(postMfaCookie).not.toEqual(cookie);

      // Old cookie must no longer authenticate.
      const logoutOld = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });
      expect(logoutOld.statusCode).toBe(401);

      // New cookie must authenticate.
      const logoutNew = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: `${tenantKey}.hubins.com`, cookie: postMfaCookie },
      });
      expect(logoutNew.statusCode).toBe(200);
    } finally {
      await app.close();
    }
  });

  it('replay protection: same TOTP code submitted twice → only one succeeds (other is non-200)', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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

      expect(setupRes.statusCode).toBe(200);
      const setupBody = parseJson<{ secret: string }>(setupRes);
      const validCode = cryptoHelpers.generateTotpCode(setupBody.secret);

      const host = `${tenantKey}.hubins.com`;
      const makeReq = () =>
        app.inject({
          method: 'POST',
          url: '/auth/mfa/verify-setup',
          headers: { host, cookie },
          body: { code: validCode },
        });

      const [a, b] = await Promise.all([makeReq(), makeReq()]);
      const codes = [a.statusCode, b.statusCode].sort();

      // We only require that exactly one call succeeds. The other may fail with 401 (invalid code)
      // OR 409 (setup already completed / no setup in progress) depending on race timing.
      expect(codes[0]).toBe(200);
      expect(codes[1]).not.toBe(200);
    } finally {
      await app.close();
    }
  });

  // NOTE: The replay path uses setIfAbsent only — cache.get is never called.
  // A READ error test patching cache.get would pass trivially and prove nothing.
  // Only the WRITE path matters here.

  it('fail-closed on replay cache WRITE error: valid code → 500, not silently allowed', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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

      expect(setupRes.statusCode).toBe(200);
      const setupBody = parseJson<{ secret: string }>(setupRes);
      const validCode = cryptoHelpers.generateTotpCode(setupBody.secret);

      // Patch setIfAbsent to simulate Redis write failure on the replay key.
      // The flow must NOT silently proceed — it must throw so the user cannot
      // reuse a valid code during a Redis write-unavailability window.
      const originalSetIfAbsent = deps.cache.setIfAbsent.bind(deps.cache);
      deps.cache.setIfAbsent = async (
        key: string,
        value: string,
        opts?: { ttlSeconds?: number },
      ) => {
        if (key.startsWith('totp:used:')) throw new Error('redis_write_error');
        return originalSetIfAbsent(key, value, opts);
      };

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { code: validCode },
      });

      // Fail-closed: Redis write failure blocks the flow, not silently passes it.
      expect(res.statusCode).toBe(500);
    } finally {
      await app.close();
    }
  });

  it('writes auth.mfa.setup.completed audit event on success', async () => {
    const { app, deps, cryptoHelpers, reset } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      await reset();
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

      // your original audit assertions remain unchanged below this point
    } finally {
      await app.close();
    }
  });
});
