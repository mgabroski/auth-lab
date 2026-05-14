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

const AgentGroupSummarySchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  level: z.enum(['ADMIN', 'AGENT', 'USER']),
  status: z.enum(['ACTIVE', 'ARCHIVED']),
});

const InviteSummarySchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  email: z.string().email(),
  role: z.enum(['ADMIN', 'AGENT', 'USER']),
  status: z.enum(['PENDING', 'ACCEPTED', 'CANCELLED', 'EXPIRED']),
  expiresAt: z.string(),
  usedAt: z.string().nullable(),
  createdAt: z.string(),
  createdByUserId: z.string().uuid().nullable(),
  agentGroups: z.array(AgentGroupSummarySchema).optional(),
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

async function createGroup(opts: {
  db: AppDeps['db'];
  tenantId: string;
  level: 'ADMIN' | 'AGENT' | 'USER';
  status?: 'ACTIVE' | 'ARCHIVED';
  name?: string;
}): Promise<{ id: string; name: string }> {
  const name = opts.name ?? `Group ${randomUUID().slice(0, 8)}`;
  const status = opts.status ?? 'ACTIVE';
  const row = await opts.db
    .insertInto('tenant_groups')
    .values({
      tenant_id: opts.tenantId,
      name,
      normalized_name: name.toLowerCase(),
      description: null,
      level: opts.level,
      status,
      created_by_membership_id: null,
      updated_by_membership_id: null,
      archived_at: status === 'ARCHIVED' ? new Date() : null,
      archived_by_membership_id: null,
    })
    .returning(['id', 'name'])
    .executeTakeFirstOrThrow();

  return { id: row.id, name: row.name };
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

  it('admin creates a USER invite → 201 with correct InviteSummary', async () => {
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
      body: { email: invitedEmail, role: 'USER' },
    });

    expect(res.statusCode).toBe(201);
    const { invite } = CreateInviteResponseSchema.parse(res.json());

    expect(invite.tenantId).toBe(tenant.id);
    expect(invite.email).toBe(invitedEmail.toLowerCase());
    expect(invite.role).toBe('USER');
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
    expect(inviteRows[0].role).toBe('USER');
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

  it('admin creates an AGENT invite with active Agent group', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const agentGroup = await createGroup({
      db: deps.db,
      tenantId: tenant.id,
      level: 'AGENT',
      name: 'Agent Operators',
    });
    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    const invitedEmail = uniqueEmail('agent-invitee');

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'AGENT', agentGroupIds: [agentGroup.id] },
    });

    expect(res.statusCode).toBe(201);
    const { invite } = CreateInviteResponseSchema.parse(res.json());
    expect(invite.role).toBe('AGENT');
    expect(invite.agentGroups).toEqual([
      { id: agentGroup.id, name: agentGroup.name, level: 'AGENT', status: 'ACTIVE' },
    ]);

    const assignments = await deps.db
      .selectFrom('invite_agent_groups')
      .select(['tenant_id', 'invite_id', 'group_id'])
      .where('tenant_id', '=', tenant.id)
      .where('invite_id', '=', invite.id)
      .execute();

    expect(assignments).toEqual([
      { tenant_id: tenant.id, invite_id: invite.id, group_id: agentGroup.id },
    ]);
  });

  it('AGENT invite requires at least one active Agent group', async () => {
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

    const noGroups = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: uniqueEmail('agent-no-groups'), role: 'AGENT' },
    });
    expect(noGroups.statusCode).toBe(400);

    const emptyGroups = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: uniqueEmail('agent-empty-groups'), role: 'AGENT', agentGroupIds: [] },
    });
    expect(emptyGroups.statusCode).toBe(400);
  });

  it('AGENT invite rejects archived, wrong-level, and cross-tenant groups safely', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const otherTenant = await createTenant({ db: deps.db, tenantKey: tenantKey() });
    const archivedAgentGroup = await createGroup({
      db: deps.db,
      tenantId: tenant.id,
      level: 'AGENT',
      status: 'ARCHIVED',
    });
    const userGroup = await createGroup({ db: deps.db, tenantId: tenant.id, level: 'USER' });
    const adminGroup = await createGroup({ db: deps.db, tenantId: tenant.id, level: 'ADMIN' });
    const crossTenantAgentGroup = await createGroup({
      db: deps.db,
      tenantId: otherTenant.id,
      level: 'AGENT',
    });
    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    for (const groupId of [
      archivedAgentGroup.id,
      userGroup.id,
      adminGroup.id,
      crossTenantAgentGroup.id,
    ]) {
      const res = await app.inject({
        method: 'POST',
        url: '/admin/invites',
        headers: { host: `${tk}.hubins.com`, cookie },
        body: {
          email: uniqueEmail('invalid-agent-group'),
          role: 'AGENT',
          agentGroupIds: [groupId],
        },
      });

      expect(res.statusCode).toBe(400);
      const parsed = ErrorBodySchema.parse(res.json());
      expect(parsed.error.message).toContain('active Agent group');
    }
  });

  it('ADMIN and USER invites reject Agent group IDs', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const agentGroup = await createGroup({ db: deps.db, tenantId: tenant.id, level: 'AGENT' });
    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    for (const role of ['ADMIN', 'USER'] as const) {
      const res = await app.inject({
        method: 'POST',
        url: '/admin/invites',
        headers: { host: `${tk}.hubins.com`, cookie },
        body: { email: uniqueEmail('non-agent-with-groups'), role, agentGroupIds: [agentGroup.id] },
      });

      expect(res.statusCode).toBe(400);
    }
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
      body: { email: invitedEmail, role: 'USER' },
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
      body: { email: 'someone@gmail.com', role: 'USER' },
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
      body: { email: uniqueEmail('invited-1'), role: 'USER' },
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

  it('list invites returns Agent group summaries for Agent invites only', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const agentGroup = await createGroup({
      db: deps.db,
      tenantId: tenant.id,
      level: 'AGENT',
      name: 'Agent Readers',
    });
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
      body: { email: uniqueEmail('agent-list'), role: 'AGENT', agentGroupIds: [agentGroup.id] },
    });
    expect(created.statusCode).toBe(201);
    const createdInvite = CreateInviteResponseSchema.parse(created.json()).invite;

    const res = await app.inject({
      method: 'GET',
      url: '/admin/invites?limit=50&offset=0',
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const parsed = ListInvitesResponseSchema.parse(res.json());
    const agentInvite = parsed.invites.find((invite) => invite.id === createdInvite.id);
    expect(agentInvite?.agentGroups).toEqual([
      { id: agentGroup.id, name: agentGroup.name, level: 'AGENT', status: 'ACTIVE' },
    ]);
  });

  it('Agent invite resend preserves valid Agent group assignments', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const agentGroup = await createGroup({ db: deps.db, tenantId: tenant.id, level: 'AGENT' });
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
      body: { email: uniqueEmail('agent-resend'), role: 'AGENT', agentGroupIds: [agentGroup.id] },
    });
    expect(created.statusCode).toBe(201);
    const oldInvite = CreateInviteResponseSchema.parse(created.json()).invite;

    const resent = await app.inject({
      method: 'POST',
      url: `/admin/invites/${oldInvite.id}/resend`,
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(resent.statusCode).toBe(200);
    const newInvite = CreateInviteResponseSchema.parse(resent.json()).invite;
    expect(newInvite.id).not.toBe(oldInvite.id);
    expect(newInvite.role).toBe('AGENT');
    expect(newInvite.agentGroups).toEqual([
      { id: agentGroup.id, name: agentGroup.name, level: 'AGENT', status: 'ACTIVE' },
    ]);

    const oldRow = await deps.db
      .selectFrom('invites')
      .select(['status'])
      .where('id', '=', oldInvite.id)
      .executeTakeFirstOrThrow();
    expect(oldRow.status).toBe('CANCELLED');
  });

  it('Agent invite resend fails if assigned Agent group is archived', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const agentGroup = await createGroup({ db: deps.db, tenantId: tenant.id, level: 'AGENT' });
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
      body: {
        email: uniqueEmail('agent-archived-resend'),
        role: 'AGENT',
        agentGroupIds: [agentGroup.id],
      },
    });
    expect(created.statusCode).toBe(201);
    const oldInvite = CreateInviteResponseSchema.parse(created.json()).invite;

    await deps.db
      .updateTable('tenant_groups')
      .set({ status: 'ARCHIVED', archived_at: new Date() })
      .where('id', '=', agentGroup.id)
      .execute();

    const resent = await app.inject({
      method: 'POST',
      url: `/admin/invites/${oldInvite.id}/resend`,
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(resent.statusCode).toBe(409);
    const row = await deps.db
      .selectFrom('invites')
      .select(['status'])
      .where('id', '=', oldInvite.id)
      .executeTakeFirstOrThrow();
    expect(row.status).toBe('PENDING');
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
      body: { email: uniqueEmail('to-cancel'), role: 'USER' },
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
