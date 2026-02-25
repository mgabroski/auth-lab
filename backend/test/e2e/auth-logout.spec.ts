/**
 * backend/test/e2e/auth-logout.spec.ts
 *
 * WHY:
 * - E2E tests for POST /auth/logout (Brick 13).
 * - Verifies session destruction, cookie clearing, audit event, and
 *   that audit failures never surface as 500s.
 *
 * RULES:
 * - Each test creates its own UUID-keyed tenant for isolation.
 * - All DB assertions scoped to user_id — never full-table counts.
 * - Rate limits are bypassed via nodeEnv: 'test' (disabled in di.ts).
 * - No role or MFA gate on logout — partial-auth sessions must be able to log out.
 */

import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';

import { buildTestApp } from '../helpers/build-test-app';
import type { AppDeps } from '../../src/app/di';

// ── Shared helpers ─────────────────────────────────────────────────────────

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

async function seedMemberSession(opts: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  deps: AppDeps;
  tenantId: string;
  tenantKey: string;
  email: string;
  password: string;
}): Promise<{ userId: string; cookie: string }> {
  const { db, passwordHasher } = opts.deps;

  const user = await db
    .insertInto('users')
    .values({ email: opts.email.toLowerCase(), name: 'Member' })
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
  const cookie = Array.isArray(raw) ? raw[0] : (raw as string);
  expect(cookie).toBeTruthy();

  return { userId: user.id, cookie };
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('POST /auth/logout', () => {
  // ── Test 1: Valid session → 200 ─────────────────────────────────────────
  it('valid session → 200 { message: "Logged out." }', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const { cookie } = await seedMemberSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `logout-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ message: 'Logged out.' });
    } finally {
      await close();
    }
  });

  // ── Test 2: Set-Cookie clears sid (Max-Age=0) ───────────────────────────
  it('response Set-Cookie header clears the sid cookie (Max-Age=0)', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const { cookie } = await seedMemberSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `logout-cookie-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);

      const setCookie = res.headers['set-cookie'];
      const cookieStr = Array.isArray(setCookie) ? setCookie[0] : (setCookie as string);
      expect(cookieStr).toMatch(/Max-Age=0/i);
      expect(cookieStr).toMatch(/sid=/);
    } finally {
      await close();
    }
  });

  // ── Test 3: Subsequent request with same cookie → 401 ───────────────────
  it('subsequent request with the same cookie after logout → 401', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const { cookie } = await seedMemberSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `logout-revoke-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      // First logout
      const logoutRes = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });
      expect(logoutRes.statusCode).toBe(200);

      // Second request with same (now-destroyed) session cookie
      const replayRes = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });
      expect(replayRes.statusCode).toBe(401);
    } finally {
      await close();
    }
  });

  // ── Test 4: audit_events row written ────────────────────────────────────
  it('writes audit_events row with action=auth.logout and metadata.sessionId', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const email = `logout-audit-${randomUUID().slice(0, 8)}@example.com`;
      const { userId, cookie } = await seedMemberSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email,
        password: 'Password123!',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });
      expect(res.statusCode).toBe(200);

      const events = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('user_id', '=', userId)
        .where('action', '=', 'auth.logout')
        .execute();

      expect(events).toHaveLength(1);
      const event = events[0];
      expect(event.tenant_id).toBe(tenant.id);

      // metadata.sessionId must be present (forensic correlation)
      const metadata = event.metadata as Record<string, unknown>;
      expect(typeof metadata['sessionId']).toBe('string');
      expect((metadata['sessionId'] as string).length).toBeGreaterThan(0);
    } finally {
      await close();
    }
  });

  // ── Test 5: No session cookie → 401 ─────────────────────────────────────
  it('no session cookie → 401', async () => {
    const { app, close } = await buildTestApp();
    try {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: 'any-tenant.hubins.com' },
      });
      expect(res.statusCode).toBe(401);
    } finally {
      await close();
    }
  });

  // ── Test 6: MEMBER session (no MFA) → 200 ───────────────────────────────
  it('MEMBER session without MFA → 200 (no role/MFA gate on logout)', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const { cookie } = await seedMemberSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `logout-member-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
    } finally {
      await close();
    }
  });

  // ── Test 7: Admin partial-auth (mfaVerified=false) → 200 ────────────────
  it('admin with mfaVerified=false (partial-auth session) → 200', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const email = `logout-admin-partial-${randomUUID().slice(0, 8)}@example.com`;
      const password = 'AdminPass123!';

      // Seed admin user WITHOUT MFA secret so login yields mfaVerified=false
      const user = await deps.db
        .insertInto('users')
        .values({ email: email.toLowerCase(), name: 'Admin' })
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
        .values({
          tenant_id: tenant.id,
          user_id: user.id,
          role: 'ADMIN',
          status: 'ACTIVE',
        })
        .execute();

      // Login → nextAction: MFA_SETUP_REQUIRED, session has mfaVerified=false
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        payload: { email, password },
      });
      expect(loginRes.statusCode).toBe(200);
      expect(loginRes.json<{ nextAction: string }>().nextAction).toBe('MFA_SETUP_REQUIRED');

      const raw = loginRes.headers['set-cookie'];
      const cookie = Array.isArray(raw) ? raw[0] : (raw as string);

      // Partial-auth admin must be able to log out — no MFA gate on logout
      const res = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
    } finally {
      await close();
    }
  });

  // ── Test 8: Audit insert throws → still 200 (Comment B locked) ──────────
  it('audit insert failure → still returns 200 (best-effort audit)', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const { cookie } = await seedMemberSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `logout-audit-fail-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      // Override auditRepo.append to simulate a DB failure on the audit insert.
      // AuthService.logout() holds a reference to deps.auditRepo, so this
      // override propagates to the service without any additional wiring.
      const originalAppend = deps.auditRepo.append.bind(deps.auditRepo);
      deps.auditRepo.append = () => {
        throw new Error('Simulated audit DB failure');
      };

      let res;
      try {
        res = await app.inject({
          method: 'POST',
          url: '/auth/logout',
          headers: { host: `${tenantKey}.hubins.com`, cookie },
        });
      } finally {
        // Restore to avoid affecting other tests
        deps.auditRepo.append = originalAppend;
      }

      // Audit failure MUST NOT surface as 500
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ message: 'Logged out.' });
    } finally {
      await close();
    }
  });
});
