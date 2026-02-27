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

// Outbox payload (encrypted)
const EncryptedInviteOutboxPayloadSchema = z.object({
  tokenEnc: z.string().min(1),
  toEmailEnc: z.string().min(1),
  tenantKey: z.string().optional(),
  inviteId: z.string().uuid(),
  role: z.enum(['ADMIN', 'MEMBER']),
});

function parseInviteOutboxPayload(
  input: unknown,
): z.infer<typeof EncryptedInviteOutboxPayloadSchema> {
  return EncryptedInviteOutboxPayloadSchema.parse(input);
}

export type InviteSummaryResponse = z.infer<typeof InviteSummarySchema>;

async function createTenant(opts: {
  db: AppDeps['db'];
  tenantKey: string;
  allowedEmailDomains?: string[];
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: false,
      member_mfa_required: false,
      allowed_email_domains: sql`${JSON.stringify(opts.allowedEmailDomains ?? [])}::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

function tenantKey(): string {
  return `t-${randomUUID().slice(0, 8)}`;
}

function uniqueEmail(prefix = 'user'): string {
  return `${prefix}-${randomUUID().slice(0, 8)}@example.com`;
}

function uniqueEmailForDomain(domain: string): string {
  return `u-${randomUUID().slice(0, 8)}@${domain}`;
}

describe('POST /admin/invites', () => {
  let app: FastifyInstance;
  let deps: AppDeps;

  beforeAll(async () => {
    const built = await buildTestApp();
    app = built.app;
    deps = built.deps;
  });

  afterAll(async () => {
    await app.close();
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

    expect(invite.id).toBeDefined();
    expect(invite.email).toBe(invitedEmail);
    expect(invite.role).toBe('MEMBER');
    expect(invite.status).toBe('PENDING');
    expect(invite.tenantId).toBe(tenant.id);
    expect(invite.usedAt).toBeNull();

    const inviteRaw = invite as Record<string, unknown>;
    expect(inviteRaw.tokenHash).toBeUndefined();

    const expiresAt = new Date(invite.expiresAt).getTime();
    const expectedExpiry = Date.now() + 7 * 24 * 60 * 60 * 1000;
    expect(Math.abs(expiresAt - expectedExpiry)).toBeLessThan(60_000);

    // Outbox row exists for invite email (durable delivery)
    const outbox = await deps.db
      .selectFrom('outbox_messages')
      .selectAll()
      .where('created_at', '>=', requestStart)
      .where('type', '=', 'invite.created')
      .where('status', '=', 'pending')
      .where('idempotency_key', 'like', `invite-created:${invite.id}:%`)
      .execute();

    expect(outbox).toHaveLength(1);

    const payload = parseInviteOutboxPayload(outbox[0].payload);
    expect(payload.tokenEnc).toMatch(/^v[0-9]+:/);
    expect(payload.toEmailEnc).toMatch(/^v[0-9]+:/);
    expect(payload.inviteId).toBe(invite.id);
    expect(payload.role).toBe('MEMBER');
  });

  it('admin creates an ADMIN invite → role=ADMIN confirmed + outbox row exists', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });
    const { cookie, userId } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    const invitedEmail = uniqueEmail('invited-admin');
    const requestStart = new Date();

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'ADMIN' },
    });

    expect(res.statusCode).toBe(201);
    const { invite } = CreateInviteResponseSchema.parse(res.json());
    expect(invite.role).toBe('ADMIN');

    const dbRow = await deps.db
      .selectFrom('invites')
      .selectAll()
      .where('id', '=', invite.id)
      .executeTakeFirstOrThrow();

    expect(dbRow.status).toBe('PENDING');
    expect(dbRow.created_by_user_id).toBe(userId);
    expect(dbRow.tenant_id).toBe(tenant.id);
    expect(dbRow.email).toBe(invitedEmail);
    expect(typeof dbRow.token_hash).toBe('string');
    expect(dbRow.token_hash.length).toBeGreaterThan(0);

    const outbox = await deps.db
      .selectFrom('outbox_messages')
      .selectAll()
      .where('created_at', '>=', requestStart)
      .where('type', '=', 'invite.created')
      .where('status', '=', 'pending')
      .where('idempotency_key', 'like', `invite-created:${invite.id}:%`)
      .execute();

    expect(outbox).toHaveLength(1);

    const payload = parseInviteOutboxPayload(outbox[0].payload);
    expect(payload.role).toBe('ADMIN');
    expect(payload.inviteId).toBe(invite.id);
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

    const invitedEmail = uniqueEmail('audit-check');

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

    expect(audits.length).toBeGreaterThanOrEqual(1);
  });

  it('tenant email domain restriction enforced', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({
      db: deps.db,
      tenantKey: tk,
      allowedEmailDomains: ['acme.com'],
    });

    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmailForDomain('acme.com'),
      password: 'Password123!',
    });

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: uniqueEmailForDomain('example.com'), role: 'MEMBER' },
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

    // create two
    await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: uniqueEmail('a'), role: 'MEMBER' },
    });
    await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: uniqueEmail('b'), role: 'MEMBER' },
    });

    const res = await app.inject({
      method: 'GET',
      url: '/admin/invites?limit=50&offset=0',
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const parsed = ListInvitesResponseSchema.parse(res.json());
    expect(parsed.invites.length).toBeGreaterThanOrEqual(2);
    for (const inv of parsed.invites) {
      expect(inv.tenantId).toBe(tenant.id);
    }
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

    // Route is DELETE /admin/invites/:inviteId (Brick 12, PR2)
    const res = await app.inject({
      method: 'DELETE',
      url: `/admin/invites/${invite.id}`,
      headers: { host: `${tk}.hubins.com`, cookie },
    });

    expect(res.statusCode).toBe(200);
    const parsed = CancelInviteResponseSchema.parse(res.json());
    expect(parsed.status).toBe('CANCELLED');
  });
});
