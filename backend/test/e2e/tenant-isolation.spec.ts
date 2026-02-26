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
    payload: { email: opts.email, password: opts.password },
  });
  expect(loginRes.statusCode).toBe(200);

  const raw = loginRes.headers['set-cookie'];
  // Cleanest fix: Remove the '!' and the 'as string' cast.
  // TypeScript already understands the types here.
  const cookie = Array.isArray(raw) ? raw[0] : raw;

  expect(cookie).toBeTruthy();

  // We cast to string here at the return level because the expect(cookie).toBeTruthy()
  // ensures it isn't undefined/null for the final result.
  return { cookie: cookie as string, userId: user.id };
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('Tenant isolation — session ↔ tenant binding', () => {
  /**
   * LOCKED: Cookie from tenant-A must NOT authenticate on a host with no tenant.
   * Source: ARCHITECTURE.md Rule C — session.tenantKey must match request tenantKey.
   * Gap closed: original middleware skipped the check when requestTenantKey was null.
   */
  it('cookie from tenant-A is silently rejected on a null-tenantKey host (localhost)', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `ta-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const email = `iso-null-${randomUUID().slice(0, 8)}@example.com`;
      const { cookie, userId } = await loginAndGetCookie({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email,
        password: 'TestPwd123!',
      });

      // Use the tenant-A cookie on a bare localhost host (null tenantKey).
      // The session middleware must reject this — authContext stays null.
      // POST /auth/logout requires auth; null authContext → 401.
      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: {
          host: 'localhost', // no tenant subdomain → requestContext.tenantKey = null
          cookie,
        },
      });

      expect(res.statusCode).toBe(401);

      // Cleanup
      await deps.db.deleteFrom('memberships').where('user_id', '=', userId).execute();
      await deps.db.deleteFrom('auth_identities').where('user_id', '=', userId).execute();
      await deps.db.deleteFrom('users').where('id', '=', userId).execute();
      await deps.db.deleteFrom('tenants').where('id', '=', tenant.id).execute();
    } finally {
      await close();
    }
  });

  /**
   * LOCKED: Cookie from tenant-A must NOT authenticate on tenant-B.
   * Source: ARCHITECTURE.md Rule C — session.tenantKey must match request tenantKey.
   * This is the canonical cross-tenant cookie reuse prevention test.
   */
  it('cookie from tenant-A is silently rejected on tenant-B host', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const keyA = `ta-${randomUUID().slice(0, 8)}`;
      const keyB = `tb-${randomUUID().slice(0, 8)}`;

      const tenantA = await createTenant({ db: deps.db, tenantKey: keyA });
      const tenantB = await createTenant({ db: deps.db, tenantKey: keyB });

      const email = `iso-cross-${randomUUID().slice(0, 8)}@example.com`;

      // Login and obtain a session cookie issued for tenant-A.
      const { cookie, userId } = await loginAndGetCookie({
        app,
        deps,
        tenantId: tenantA.id,
        tenantKey: keyA,
        email,
        password: 'TestPwd123!',
      });

      // Use the tenant-A cookie on the tenant-B host.
      // session.tenantKey = keyA, requestTenantKey = keyB → mismatch → 401.
      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: {
          host: `${keyB}.hubins.com`, // tenant-B host
          cookie, // cookie issued for tenant-A
        },
      });

      expect(res.statusCode).toBe(401);

      // Verify the same cookie IS valid on tenant-A (control case).
      const resOk = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: {
          host: `${keyA}.hubins.com`,
          cookie,
        },
      });
      expect(resOk.statusCode).toBe(200);

      // Cleanup
      await deps.db.deleteFrom('memberships').where('user_id', '=', userId).execute();
      await deps.db.deleteFrom('auth_identities').where('user_id', '=', userId).execute();
      await deps.db.deleteFrom('users').where('id', '=', userId).execute();
      await deps.db.deleteFrom('tenants').where('id', '=', tenantA.id).execute();
      await deps.db.deleteFrom('tenants').where('id', '=', tenantB.id).execute();
    } finally {
      await close();
    }
  });

  /**
   * Sanity / control: cookie from tenant-A authenticates correctly on tenant-A.
   * If this fails, something is broken in the middleware itself — not just isolation.
   */
  it('cookie from tenant-A authenticates correctly on the same tenant-A host', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `ta-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const email = `iso-ok-${randomUUID().slice(0, 8)}@example.com`;
      const { cookie, userId } = await loginAndGetCookie({
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

      // Cleanup (logout already destroyed the session; just clean DB)
      await deps.db.deleteFrom('memberships').where('user_id', '=', userId).execute();
      await deps.db.deleteFrom('auth_identities').where('user_id', '=', userId).execute();
      await deps.db.deleteFrom('users').where('id', '=', userId).execute();
      await deps.db.deleteFrom('tenants').where('id', '=', tenant.id).execute();
    } finally {
      await close();
    }
  });
});
