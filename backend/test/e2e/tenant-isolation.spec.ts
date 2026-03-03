/**
 * backend/test/e2e/tenant-isolation.spec.ts
 *
 * WHY:
 * - Locks the tenant ↔ session binding behaviour established in session.middleware.ts.
 * - These are SECURITY tests: a cookie from tenant-A must NEVER authenticate
 *   requests on tenant-B or on a host with no tenant (e.g. bare localhost).
 * - See also: ARCHITECTURE.md Rule C, session.middleware.ts canonical comment.
 *
 * - The original middleware condition guarded with `requestTenantKey &&`, meaning
 *   a session cookie from tenant-A authenticated silently on a null-tenantKey host
 *   (e.g. localhost). This was a security gap.
 * - Fix applied: changed to `session.tenantKey !== requestTenantKey` — exact equality
 *   with no conditional guard. All mismatch permutations now correctly reject.
 * - These tests verified the gap and confirm the fix.
 *
 * RULES:
 * - Each test creates its own UUID-keyed tenants for isolation.
 * - Tests use POST /auth/logout as the protected probe endpoint:
 *   it requires only a valid session (no role, no MFA gate).
 * - 401 = unauthenticated (authContext null — session middleware rejected the cookie).
 * - Rate limits disabled in test mode (nodeEnv: 'test').
 */

import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';

import { buildTestApp } from '../helpers/build-test-app';
import type { AppDeps } from '../../src/app/di';

// ── Helpers ────────────────────────────────────────────────────────────────

async function createTenant(opts: { db: AppDeps['db']; tenantKey: string }) {
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

/**
 * Seeds the minimum DB state and logs in via HTTP to obtain a session cookie.
 * Returns the cookie header value (the raw Set-Cookie string).
 */
async function loginAndGetCookie(opts: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  deps: AppDeps;
  tenantId: string;
  tenantKey: string;
  email: string;
  password: string;
}): Promise<{ cookie: string; userId: string }> {
  const { db, passwordHasher } = opts.deps;

  const user = await db
    .insertInto('users')
    .values({ email: opts.email.toLowerCase(), name: 'Test User' })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const hash = await passwordHasher.hash(opts.password);
  await db
    .insertInto('auth_identities')
    .values({
      user_id: user.id,
      provider: 'password',
      password_hash: hash,
      provider_subject: null,
    })
    .execute();

  await db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: 'MEMBER',
      status: 'ACTIVE',
    })
    .execute();

  const loginRes = await opts.app.inject({
    method: 'POST',
    url: '/auth/login',
    headers: { host: `${opts.tenantKey}.hubins.com` },
    body: { email: opts.email, password: opts.password },
  });

  expect(loginRes.statusCode).toBe(200);

  const raw = loginRes.headers['set-cookie'];
  const cookie = Array.isArray(raw) ? raw[0] : raw;

  expect(typeof cookie).toBe('string');

  return { cookie: cookie as string, userId: user.id };
}

describe('Tenant isolation — session ↔ tenant binding', () => {
  it('cookie from tenant-A is silently rejected on a null-tenantKey host (localhost)', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `ta-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const email = `iso-${randomUUID().slice(0, 8)}@example.com`;
      const { cookie } = await loginAndGetCookie({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email,
        password: 'TestPwd123!',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: {
          host: `localhost`,
          cookie,
        },
      });

      // 401 = session rejected due to tenantKey mismatch (cookie was bound to tenant-A).
      expect(res.statusCode).toBe(401);
    } finally {
      await close();
    }
  });

  it('cookie from tenant-A is rejected on a different tenant-B host', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantAKey = `ta-${randomUUID().slice(0, 8)}`;
      const tenantBKey = `tb-${randomUUID().slice(0, 8)}`;

      const tenantA = await createTenant({ db: deps.db, tenantKey: tenantAKey });
      await createTenant({ db: deps.db, tenantKey: tenantBKey });

      const email = `iso-cross-${randomUUID().slice(0, 8)}@example.com`;
      const { cookie } = await loginAndGetCookie({
        app,
        deps,
        tenantId: tenantA.id,
        tenantKey: tenantAKey,
        email,
        password: 'TestPwd123!',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: {
          host: `${tenantBKey}.hubins.com`,
          cookie,
        },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await close();
    }
  });

  /**
   * Sanity check: a cookie must authenticate correctly on the same tenant host.
   * If this fails, something is broken in the middleware itself — not just isolation.
   */
  it('cookie from tenant-A authenticates correctly on the same tenant-A host', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `ta-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const email = `iso-ok-${randomUUID().slice(0, 8)}@example.com`;
      const { cookie } = await loginAndGetCookie({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email,
        password: 'TestPwd123!',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: {
          host: `${tenantKey}.hubins.com`,
          cookie,
        },
      });

      // 200 = session was authenticated correctly.
      expect(res.statusCode).toBe(200);

      // No per-test cleanup: buildTestApp() + resetDb() provide deterministic isolation.
    } finally {
      await close();
    }
  });
});
