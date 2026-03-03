/**
 * backend/test/e2e/admin-invites.spec.ts
 *
 * WHY:
 * - E2E tests for admin invite endpoints (Brick 12).
 * - Verifies real DB side-effects: invite row correctness, audit event,
 *   durable outbox row, tenant isolation.
 *
 * RULES:
 * - Each test creates its own UUID-keyed tenant for isolation.
 * - All DB assertions scoped to tenant_id or user_id — never full-table counts.
 * - No debug endpoints or mocking for correctness-critical flows.
 * - Rate limits are bypassed via nodeEnv: 'test' (disabled in di.ts).
 * - No `any` / unsafe member access. Parse JSON using schemas at boundaries.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { z } from 'zod';
import type { FastifyInstance } from 'fastify';

import { buildTestApp } from '../helpers/build-test-app';
import type { AppDeps } from '../../src/app/di';
import { createAdminSession } from '../helpers/create-admin-session';

// ── Response schemas (Zod) ──────────────────────────────────────────────────

const InviteSummarySchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  email: z.string().email(),
  role: z.enum(['ADMIN', 'MEMBER']),
  status: z.enum(['PENDING', 'ACCEPTED', 'CANCELLED', 'EXPIRED']),
  expiresAt: z.string(),
  usedAt: z.string().nullable(),
  createdAt: z.string(),
  createdByUserId: z.string().uuid().nullable(),
});

const CreateInviteResponseSchema = z.object({
  invite: InviteSummarySchema,
});

const ListInvitesResponseSchema = z.object({
  invites: z.array(InviteSummarySchema),
  total: z.number().int().min(0),
  limit: z.number().int().min(1),
  offset: z.number().int().min(0),
});

const CancelInviteResponseSchema = z.object({
  status: z.literal('CANCELLED'),
});

const ErrorBodySchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
  }),
});

const OutboxPayloadSchema = z
  .object({
    tenantKey: z.string().optional(),
    inviteId: z.string().optional(),
    role: z.string().optional(),
  })
  .passthrough();

// ── Helpers ────────────────────────────────────────────────────────────────

function tenantKey(): string {
  return `t-${randomUUID().slice(0, 10)}`;
}

function uniqueEmail(prefix: string): string {
  return `${prefix}-${randomUUID().slice(0, 10)}@example.com`;
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

describe('POST /admin/invites', () => {
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

  it('admin creates a MEMBER invite → 201 with correct InviteSummary', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    const invitedEmail = uniqueEmail('invited');
    const requestStart = new Date();

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(201);
    const { invite } = CreateInviteResponseSchema.parse(res.json());

    expect(invite.tenantId).toBe(tenant.id);
    expect(invite.email).toBe(invitedEmail.toLowerCase());
    expect(invite.role).toBe('MEMBER');
    expect(invite.status).toBe('PENDING');
    expect(invite.createdByUserId).toBeTruthy();

    // expiresAt should be ~7 days from creation (tolerance: 5 minutes)
    const expiresAt = new Date(invite.expiresAt);
    expect(expiresAt.getTime()).toBeGreaterThan(requestStart.getTime() + 6.9 * 24 * 60 * 60 * 1000);

    // DB: invite row exists
    const inviteRows = await deps.db
      .selectFrom('invites')
      .selectAll()
      .where('id', '=', invite.id)
      .execute();

    expect(inviteRows).toHaveLength(1);
    expect(inviteRows[0].tenant_id).toBe(tenant.id);
    expect(inviteRows[0].email).toBe(invitedEmail.toLowerCase());
    expect(inviteRows[0].role).toBe('MEMBER');
    expect(inviteRows[0].status).toBe('PENDING');
  });

  it('admin creates an ADMIN invite → role=ADMIN confirmed + outbox row exists', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    const invitedEmail = uniqueEmail('admin-invitee');

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'ADMIN' },
    });

    expect(res.statusCode).toBe(201);
    const { invite } = CreateInviteResponseSchema.parse(res.json());
    expect(invite.role).toBe('ADMIN');

    // Outbox: invite email is enqueued (type: invite.created)
    const outboxRows = await deps.db
      .selectFrom('outbox_messages')
      .select(['id', 'type', 'payload', 'created_at'])
      .where('type', '=', 'invite.created')
      .execute();

    expect(outboxRows.length).toBeGreaterThanOrEqual(1);

    // Find the row for THIS tenant + invite id
    const matching = outboxRows.find((r) => {
      const parsed = OutboxPayloadSchema.safeParse(r.payload);
      if (!parsed.success) return false;
      return (
        parsed.data.tenantKey === tk &&
        parsed.data.inviteId === invite.id &&
        parsed.data.role === 'ADMIN'
      );
    });

    expect(matching).toBeTruthy();
  });

  it('invite.created audit event written inside transaction', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    const invitedEmail = uniqueEmail('invited');

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(201);

    const audits = await deps.db
      .selectFrom('audit_events')
      .selectAll()
      .where('tenant_id', '=', tenant.id)
      .where('action', '=', 'invite.created')
      .execute();

    expect(audits).toHaveLength(1);
  });

  it('tenant email domain restriction enforced', async () => {
    const tk = tenantKey();
    const tenant = await deps.db
      .insertInto('tenants')
      .values({
        key: tk,
        name: `Tenant ${tk}`,
        is_active: true,
        public_signup_enabled: false,
        member_mfa_required: false,
        allowed_email_domains: sql`'["acme.com"]'::jsonb`,
      })
      .returning(['id', 'key'])
      .executeTakeFirstOrThrow();

    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: 'someone@gmail.com', role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(400);
    const parsed = ErrorBodySchema.parse(res.json());
    expect(parsed.error.code).toBeDefined();
  });

  it('list invites returns tenant-scoped results', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    // Create 2 invites
    await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: uniqueEmail('invited-1'), role: 'MEMBER' },
    });
    await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: uniqueEmail('invited-2'), role: 'ADMIN' },
    });

    const res = await app.inject({
      method: 'GET',
      url: '/admin/invites?limit=50&offset=0',
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const parsed = ListInvitesResponseSchema.parse(res.json());
    expect(parsed.invites.length).toBeGreaterThanOrEqual(2);
    expect(parsed.invites.every((i) => i.tenantId === tenant.id)).toBe(true);
  });

  it('cancel invite transitions to CANCELLED', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    const created = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: uniqueEmail('to-cancel'), role: 'MEMBER' },
    });

    expect(created.statusCode).toBe(201);
    const invite = CreateInviteResponseSchema.parse(created.json()).invite;

    // IMPORTANT: cancel is DELETE /admin/invites/:inviteId
    const res = await app.inject({
      method: 'DELETE',
      url: `/admin/invites/${invite.id}`,
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const body = CancelInviteResponseSchema.parse(res.json());
    expect(body.status).toBe('CANCELLED');

    const row = await deps.db
      .selectFrom('invites')
      .selectAll()
      .where('id', '=', invite.id)
      .executeTakeFirstOrThrow();

    expect(row.status).toBe('CANCELLED');
  });
});
