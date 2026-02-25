/**
 * backend/test/e2e/admin-audit-events.spec.ts
 *
 * WHY:
 * - E2E tests for GET /admin/audit-events (Brick 13).
 * - Verifies pagination, filtering, tenant isolation, auth guards,
 *   and that no credential data leaks in responses.
 *
 * RULES:
 * - Each test creates its own UUID-keyed tenant for isolation.
 * - All DB assertions scoped to tenant_id — never full-table counts.
 * - Rate limits are bypassed via nodeEnv: 'test' (disabled in di.ts).
 */

import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';

import { buildTestApp } from '../helpers/build-test-app';
import { createAdminSession } from '../helpers/create-admin-session';
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
 * Inserts audit_events rows directly for a given tenant.
 * Bypasses the service layer so tests control exact action/metadata/user.
 */
async function seedAuditEvents(
  db: AppDeps['db'],
  events: Array<{
    tenantId: string;
    action: string;
    userId?: string;
    membershipId?: string;
    metadata?: Record<string, unknown>;
    createdAt?: Date;
  }>,
): Promise<void> {
  for (const ev of events) {
    await db
      .insertInto('audit_events')
      .values({
        tenant_id: ev.tenantId,
        action: ev.action,
        user_id: ev.userId ?? null,
        membership_id: ev.membershipId ?? null,
        request_id: randomUUID(),
        ip: '127.0.0.1',
        user_agent: 'test-agent',
        metadata: sql`${JSON.stringify(ev.metadata ?? {})}::jsonb`,
        // Override created_at for deterministic ordering tests
        ...(ev.createdAt ? { created_at: ev.createdAt } : {}),
      })
      .execute();
  }
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('GET /admin/audit-events', () => {
  // ── Test 1: Admin → 200 with correct shape ─────────────────────────────
  it('admin with MFA → 200 with { events, total, limit, offset }', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ events: unknown[]; total: number; limit: number; offset: number }>();
      expect(typeof body.total).toBe('number');
      expect(typeof body.limit).toBe('number');
      expect(typeof body.offset).toBe('number');
      expect(Array.isArray(body.events)).toBe(true);
    } finally {
      await close();
    }
  });

  // ── Test 2: Empty tenant → 200 { events: [], total: 0 } ────────────────
  it('empty tenant → 200 { events: [], total: 0 }', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      // Delete ALL audit events for this tenant (including those from createAdminSession)
      await deps.db.deleteFrom('audit_events').where('tenant_id', '=', tenant.id).execute();

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ events: unknown[]; total: number }>();
      expect(body.events).toHaveLength(0);
      expect(body.total).toBe(0);
    } finally {
      await close();
    }
  });

  // ── Test 3: limit=2 offset=0 → first 2 events ─────────────────────────
  it('limit=2 offset=0 → returns first 2 events', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      // Seed 3 additional events so we have enough to paginate
      await seedAuditEvents(deps.db, [
        { tenantId: tenant.id, action: 'test.event.1' },
        { tenantId: tenant.id, action: 'test.event.2' },
        { tenantId: tenant.id, action: 'test.event.3' },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events?limit=2&offset=0',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ events: unknown[]; total: number; limit: number; offset: number }>();
      expect(body.events).toHaveLength(2);
      expect(body.limit).toBe(2);
      expect(body.offset).toBe(0);
      expect(body.total).toBeGreaterThanOrEqual(3);
    } finally {
      await close();
    }
  });

  // ── Test 4: offset=2 → next page ──────────────────────────────────────
  it('offset=2 → returns next page', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      await seedAuditEvents(deps.db, [
        { tenantId: tenant.id, action: 'test.event.a' },
        { tenantId: tenant.id, action: 'test.event.b' },
        { tenantId: tenant.id, action: 'test.event.c' },
        { tenantId: tenant.id, action: 'test.event.d' },
      ]);

      const page1 = await app.inject({
        method: 'GET',
        url: '/admin/audit-events?limit=2&offset=0',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });
      const page2 = await app.inject({
        method: 'GET',
        url: '/admin/audit-events?limit=2&offset=2',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(page1.statusCode).toBe(200);
      expect(page2.statusCode).toBe(200);

      const ids1 = page1.json<{ events: { id: string }[] }>().events.map((e) => e.id);
      const ids2 = page2.json<{ events: { id: string }[] }>().events.map((e) => e.id);

      // Pages must not overlap
      const overlap = ids1.filter((id) => ids2.includes(id));
      expect(overlap).toHaveLength(0);
    } finally {
      await close();
    }
  });

  // ── Test 5: limit=101 → 400 (Comment A locked) ────────────────────────
  it('limit=101 → 400 validation error', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events?limit=101',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(400);
    } finally {
      await close();
    }
  });

  // ── Test 6: action filter → matching events only ───────────────────────
  it('action=auth.login.failed → returns only matching events', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      await seedAuditEvents(deps.db, [
        { tenantId: tenant.id, action: 'auth.login.failed' },
        { tenantId: tenant.id, action: 'auth.login.failed' },
        { tenantId: tenant.id, action: 'auth.login.success' },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events?action=auth.login.failed',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ events: { action: string }[] }>();
      expect(body.events.every((e) => e.action === 'auth.login.failed')).toBe(true);
    } finally {
      await close();
    }
  });

  // ── Test 7: userId filter → matching events only ───────────────────────
  it('userId filter → returns only events for that user', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { userId, cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      const otherUserId = randomUUID();

      await seedAuditEvents(deps.db, [
        { tenantId: tenant.id, action: 'test.event', userId },
        { tenantId: tenant.id, action: 'test.event', userId },
        { tenantId: tenant.id, action: 'test.event', userId: otherUserId },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: `/admin/audit-events?userId=${userId}`,
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ events: { userId: string | null }[] }>();
      expect(body.events.every((e) => e.userId === userId)).toBe(true);
    } finally {
      await close();
    }
  });

  // ── Test 8: from/to date range → events in range only ─────────────────
  it('from/to filter → returns only events within the date range', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      const t1 = new Date('2025-01-01T10:00:00.000Z');
      const t2 = new Date('2025-06-15T10:00:00.000Z');
      const t3 = new Date('2025-12-31T10:00:00.000Z');

      await seedAuditEvents(deps.db, [
        { tenantId: tenant.id, action: 'test.before', createdAt: t1 },
        { tenantId: tenant.id, action: 'test.inside', createdAt: t2 },
        { tenantId: tenant.id, action: 'test.after', createdAt: t3 },
      ]);

      const from = '2025-03-01T00:00:00.000Z';
      const to = '2025-09-01T00:00:00.000Z';

      const res = await app.inject({
        method: 'GET',
        url: `/admin/audit-events?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&action=test.inside`,
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ events: { action: string }[] }>();
      expect(body.events.every((e) => e.action === 'test.inside')).toBe(true);
    } finally {
      await close();
    }
  });

  // ── Test 9: MEMBER role → 403 ─────────────────────────────────────────
  it('MEMBER role → 403 Insufficient role', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      // Seed a MEMBER user with a session
      const email = `member-${randomUUID().slice(0, 8)}@example.com`;
      const password = 'Password123!';

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
        payload: { email, password },
      });
      const raw = loginRes.headers['set-cookie'];
      const cookie = Array.isArray(raw) ? raw[0] : (raw as string);

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  // ── Test 10: Admin, mfaVerified=false → 403 ───────────────────────────
  it('admin without MFA verified → 403 MFA verification required', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      // Admin with no MFA secret → mfaVerified=false on login
      const email = `admin-nomfa-${randomUUID().slice(0, 8)}@example.com`;
      const password = 'AdminPass123!';

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
        .values({ tenant_id: tenant.id, user_id: user.id, role: 'ADMIN', status: 'ACTIVE' })
        .execute();

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        payload: { email, password },
      });
      const raw = loginRes.headers['set-cookie'];
      const cookie = Array.isArray(raw) ? raw[0] : (raw as string);

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  // ── Test 11: No session → 401 ──────────────────────────────────────────
  it('no session → 401', async () => {
    const { app, close } = await buildTestApp();
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events',
        headers: { host: 'any-tenant.hubins.com' },
      });
      expect(res.statusCode).toBe(401);
    } finally {
      await close();
    }
  });

  // ── Test 12: Tenant isolation ─────────────────────────────────────────
  it('events from another tenant are never returned', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const keyA = `t-${randomUUID().slice(0, 8)}`;
      const keyB = `t-${randomUUID().slice(0, 8)}`;
      const tenantA = await createTenant({ db: deps.db, tenantKey: keyA });
      const tenantB = await createTenant({ db: deps.db, tenantKey: keyB });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenantA.id,
        tenantKey: keyA,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      // Seed a uniquely identifiable event for tenant B only
      const tenantBAction = `tenant-b-secret-${randomUUID().slice(0, 8)}`;
      await seedAuditEvents(deps.db, [{ tenantId: tenantB.id, action: tenantBAction }]);

      const res = await app.inject({
        method: 'GET',
        url: `/admin/audit-events?action=${tenantBAction}`,
        headers: { host: `${keyA}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ events: unknown[]; total: number }>();
      // Tenant A must see zero results — tenant B's events are invisible
      expect(body.events).toHaveLength(0);
      expect(body.total).toBe(0);
    } finally {
      await close();
    }
  });

  // ── Test 13: Invalid userId (not UUID) → 400 ──────────────────────────
  it('invalid userId (not UUID) → 400', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events?userId=not-a-uuid',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(400);
    } finally {
      await close();
    }
  });

  // ── Test 14: Invalid from (not ISO) → 400 ─────────────────────────────
  it('invalid from (not ISO datetime) → 400', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events?from=not-a-date',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(400);
    } finally {
      await close();
    }
  });

  // ── Test 15: No credential data in response ────────────────────────────
  it('response events never contain tokenHash, passwordHash, or credential fields', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);

      const body = res.json<{ events: Record<string, unknown>[] }>();
      const forbidden = [
        'tokenHash',
        'token_hash',
        'passwordHash',
        'password_hash',
        'tenantId',
        'tenant_id',
      ];

      for (const event of body.events) {
        for (const field of forbidden) {
          expect(event).not.toHaveProperty(field);
        }
      }
    } finally {
      await close();
    }
  });

  // ── Test 16: Sorted created_at DESC — newest is events[0] ─────────────
  it('events are sorted created_at DESC — newest event is events[0]', async () => {
    const { app, deps, close } = await buildTestApp();
    try {
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const { cookie } = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'AdminPass123!',
      });

      const marker = `sort-test-${randomUUID().slice(0, 8)}`;

      await seedAuditEvents(deps.db, [
        { tenantId: tenant.id, action: marker, createdAt: new Date('2025-01-01T00:00:00.000Z') },
        { tenantId: tenant.id, action: marker, createdAt: new Date('2025-06-01T00:00:00.000Z') },
        { tenantId: tenant.id, action: marker, createdAt: new Date('2025-12-01T00:00:00.000Z') },
      ]);

      const res = await app.inject({
        method: 'GET',
        url: `/admin/audit-events?action=${marker}`,
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ events: { createdAt: string }[] }>();
      expect(body.events).toHaveLength(3);

      // Verify descending order
      const dates = body.events.map((e) => new Date(e.createdAt).getTime());
      for (let i = 0; i < dates.length - 1; i++) {
        expect(dates[i]).toBeGreaterThanOrEqual(dates[i + 1]);
      }

      // Newest (Dec) must be first
      expect(body.events[0].createdAt).toContain('2025-12');
    } finally {
      await close();
    }
  });
});
