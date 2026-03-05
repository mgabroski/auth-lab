import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { z } from 'zod';
import type { FastifyInstance } from 'fastify';

import { buildTestApp } from '../helpers/build-test-app';
import type { AppDeps } from '../../src/app/di';
import { SESSION_COOKIE_NAME } from '../../src/shared/session/session.types';

// ── Response schemas (Zod) ──────────────────────────────────────────────────

const AuditEventSchema = z.object({
  id: z.string().uuid(),
  action: z.string(),
  userId: z.string().uuid().nullable(),
  membershipId: z.string().uuid().nullable(),
  requestId: z.string().nullable(),
  ip: z.string().nullable(),
  userAgent: z.string().nullable(),
  metadata: z.record(z.unknown()),
  createdAt: z.string(),
});

const ListAuditEventsResponseSchema = z.object({
  events: z.array(AuditEventSchema),
  total: z.number().int().min(0),
  limit: z.number().int().min(1),
  offset: z.number().int().min(0),
});

// ── Helpers ────────────────────────────────────────────────────────────────

function tenantKey(): string {
  return `t-${randomUUID().slice(0, 10)}`;
}

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

// Create an authenticated ADMIN session without driving /auth/login or MFA flows.
// This keeps audit tests focused on audit behavior (no unrelated auth audit noise).
async function createAdminCookie(opts: {
  deps: AppDeps;
  tenantId: string;
  tenantKey: string;
}): Promise<{ cookie: string; userId: string; membershipId: string }> {
  const { db, sessionStore } = opts.deps;

  const user = await db
    .insertInto('users')
    .values({
      email: `admin-${randomUUID().slice(0, 10)}@example.com`,
      name: 'Admin',
      email_verified: true,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const membership = await db
    .insertInto('memberships')
    .values({ tenant_id: opts.tenantId, user_id: user.id, role: 'ADMIN', status: 'ACTIVE' })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const sessionId = await sessionStore.create({
    tenantId: opts.tenantId,
    tenantKey: opts.tenantKey,
    userId: user.id,
    membershipId: membership.id,
    role: 'ADMIN',
    mfaVerified: true,
    emailVerified: true,
    createdAt: new Date().toISOString(),
  });

  return {
    cookie: `${SESSION_COOKIE_NAME}=${sessionId}`,
    userId: user.id,
    membershipId: membership.id,
  };
}

describe('GET /admin/audit-events', () => {
  let app: FastifyInstance;
  let deps: AppDeps;
  let close: () => Promise<void>;

  beforeAll(async () => {
    const built = await buildTestApp();
    app = built.app;
    deps = built.deps;
    close = built.close;
  });

  afterAll(async () => {
    await close();
  });

  it('empty tenant → 200 { events: [], total: 0 }', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });

    const { cookie } = await createAdminCookie({ deps, tenantId: tenant.id, tenantKey: tk });

    const res = await app.inject({
      method: 'GET',
      url: '/admin/audit-events?limit=50&offset=0',
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = ListAuditEventsResponseSchema.parse(res.json());
    expect(body.events).toHaveLength(0);
    expect(body.total).toBe(0);
  });

  it('action filter → returns only matching actions', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });

    const { cookie } = await createAdminCookie({ deps, tenantId: tenant.id, tenantKey: tk });

    await deps.db
      .insertInto('audit_events')
      .values([
        { tenant_id: tenant.id, action: 'test.match', metadata: sql`'{}'::jsonb` },
        { tenant_id: tenant.id, action: 'test.nope', metadata: sql`'{}'::jsonb` },
      ])
      .execute();

    const res = await app.inject({
      method: 'GET',
      url: '/admin/audit-events?limit=50&offset=0&action=test.match',
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = ListAuditEventsResponseSchema.parse(res.json());
    expect(body.total).toBe(1);
    expect(body.events).toHaveLength(1);
    expect(body.events[0].action).toBe('test.match');
  });

  it('userId filter → returns only matching userId', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });

    const { userId, cookie } = await createAdminCookie({
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
    });

    await deps.db
      .insertInto('audit_events')
      .values([
        { tenant_id: tenant.id, action: 'test.match', user_id: userId, metadata: sql`'{}'::jsonb` },
        {
          tenant_id: tenant.id,
          action: 'test.nope',
          user_id: randomUUID(),
          metadata: sql`'{}'::jsonb`,
        },
      ])
      .execute();

    const res = await app.inject({
      method: 'GET',
      url: `/admin/audit-events?limit=50&offset=0&userId=${userId}`,
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = ListAuditEventsResponseSchema.parse(res.json());
    expect(body.total).toBe(1);
    expect(body.events).toHaveLength(1);
    expect(body.events[0].userId).toBe(userId);
  });

  it('limit is capped at 100', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });

    const { cookie } = await createAdminCookie({ deps, tenantId: tenant.id, tenantKey: tk });

    const res = await app.inject({
      method: 'GET',
      url: '/admin/audit-events?limit=101&offset=0',
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = ListAuditEventsResponseSchema.parse(res.json());
    expect(body.limit).toBe(100);
  });

  it('from/to filter → returns only events within the date range', async () => {
    const tkA = tenantKey();
    const tenantA = await createTenant({ db: deps.db, tenantKey: tkA });

    const now = new Date();
    const from = new Date(now.getTime() - 2 * 60 * 60 * 1000);
    const to = new Date(now.getTime() - 1 * 60 * 60 * 1000);

    await deps.db
      .insertInto('audit_events')
      .values([
        {
          tenant_id: tenantA.id,
          action: 'test.before',
          created_at: new Date(from.getTime() - 60_000),
          metadata: sql`'{}'::jsonb`,
        },
        {
          tenant_id: tenantA.id,
          action: 'test.inside',
          created_at: new Date(from.getTime() + 60_000),
          metadata: sql`'{}'::jsonb`,
        },
        {
          tenant_id: tenantA.id,
          action: 'test.inside',
          created_at: new Date(to.getTime() - 60_000),
          metadata: sql`'{}'::jsonb`,
        },
        {
          tenant_id: tenantA.id,
          action: 'test.after',
          created_at: new Date(to.getTime() + 60_000),
          metadata: sql`'{}'::jsonb`,
        },
      ])
      .execute();

    const { cookie } = await createAdminCookie({ deps, tenantId: tenantA.id, tenantKey: tkA });

    const url = `/admin/audit-events?limit=50&offset=0&from=${from.toISOString()}&to=${to.toISOString()}`;
    const res = await app.inject({
      method: 'GET',
      url,
      headers: { host: `${tkA}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = ListAuditEventsResponseSchema.parse(res.json());
    expect(body.events.every((e) => e.action === 'test.inside')).toBe(true);
  });

  it('events from another tenant are never returned', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });

    const otherTk = tenantKey();
    const otherTenant = await createTenant({ db: deps.db, tenantKey: otherTk });

    await deps.db
      .insertInto('audit_events')
      .values([{ tenant_id: otherTenant.id, action: 'other.tenant', metadata: sql`'{}'::jsonb` }])
      .execute();

    const { cookie } = await createAdminCookie({ deps, tenantId: tenant.id, tenantKey: tk });

    const res = await app.inject({
      method: 'GET',
      url: '/admin/audit-events?limit=50&offset=0',
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = ListAuditEventsResponseSchema.parse(res.json());
    expect(body.total).toBe(0);
    expect(body.events).toHaveLength(0);
  });

  it('response events never contain tokenHash, passwordHash, or credential fields', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });

    await deps.db
      .insertInto('audit_events')
      .values([
        {
          tenant_id: tenant.id,
          action: 'test.sensitive',
          metadata: sql`'{"tokenHash":"x","passwordHash":"y","credentials":{"a":1},"safe":"ok"}'::jsonb`,
        },
      ])
      .execute();

    const { cookie } = await createAdminCookie({ deps, tenantId: tenant.id, tenantKey: tk });

    const res = await app.inject({
      method: 'GET',
      url: '/admin/audit-events?limit=50&offset=0',
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = ListAuditEventsResponseSchema.parse(res.json());

    const serialized = JSON.stringify(body.events);
    expect(serialized.includes('tokenHash')).toBe(false);
    expect(serialized.includes('passwordHash')).toBe(false);
    expect(serialized.includes('credentials')).toBe(false);
    expect(serialized.includes('safe')).toBe(true);
  });

  it('events are sorted created_at DESC — newest event is events[0]', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });

    const base = new Date();
    await deps.db
      .insertInto('audit_events')
      .values([
        {
          tenant_id: tenant.id,
          action: 'test.oldest',
          created_at: new Date(base.getTime() - 3_000),
          metadata: sql`'{}'::jsonb`,
        },
        {
          tenant_id: tenant.id,
          action: 'test.middle',
          created_at: new Date(base.getTime() - 2_000),
          metadata: sql`'{}'::jsonb`,
        },
        {
          tenant_id: tenant.id,
          action: 'test.newest',
          created_at: new Date(base.getTime() - 1_000),
          metadata: sql`'{}'::jsonb`,
        },
      ])
      .execute();

    const { cookie } = await createAdminCookie({ deps, tenantId: tenant.id, tenantKey: tk });

    const res = await app.inject({
      method: 'GET',
      url: '/admin/audit-events?limit=50&offset=0',
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = ListAuditEventsResponseSchema.parse(res.json());

    expect(body.events).toHaveLength(3);
    expect(body.events[0].action).toBe('test.newest');
    expect(new Date(body.events[0].createdAt).getTime()).toBeGreaterThanOrEqual(
      new Date(body.events[1].createdAt).getTime(),
    );
    expect(new Date(body.events[1].createdAt).getTime()).toBeGreaterThanOrEqual(
      new Date(body.events[2].createdAt).getTime(),
    );
  });
});
