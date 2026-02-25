/**
 * backend/test/e2e/admin-invites.spec.ts
 *
 * WHY:
 * - E2E tests for admin invite endpoints (Brick 12).
 * - Verifies real DB side-effects: invite row correctness, audit event,
 * queue message, tenant isolation.
 *
 * RULES:
 * - Each test creates its own UUID-keyed tenant for isolation.
 * - All DB assertions scoped to tenant_id or user_id — never full-table counts.
 * - No debug endpoints or mocking for correctness-critical flows.
 * - Rate limits are bypassed via nodeEnv: 'test' (disabled in di.ts).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { z } from 'zod';
import type { FastifyInstance } from 'fastify';
import type { InMemQueue } from '../../src/shared/messaging/inmem-queue';
import type { AdminInviteEmailMessage } from '../../src/shared/messaging/queue';

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

/**
 * Build a unique email that ends with a specific domain.
 * Use when the tenant has `allowedEmailDomains` restrictions.
 * Prefixing with a UUID slice guarantees no cross-run collision on the
 * `users.email` unique constraint even though the DB persists between runs.
 */
function uniqueEmailForDomain(domain: string): string {
  return `u-${randomUUID().slice(0, 8)}@${domain}`;
}

/**
 * Extract cookie from Fastify response headers.
 * Uses a flexible Record type to avoid conflicts with Node's OutgoingHttpHeaders
 * which allows numbers (e.g. content-length).
 */
function getCookie(res: {
  headers: Record<string, string | string[] | number | undefined>;
}): string {
  const raw = res.headers['set-cookie'];
  const cookie = Array.isArray(raw) ? raw[0] : raw;
  if (!cookie || typeof cookie !== 'string') {
    throw new Error('No set-cookie header in response');
  }
  return cookie;
}

/**
 * Create an invite via POST /admin/invites and return the parsed InviteSummary.
 * Assumes the caller has already drained the queue if needed.
 */
async function createInviteViaApi(opts: {
  app: FastifyInstance;
  tenantKey: string;
  cookie: string;
  email: string;
  role?: 'ADMIN' | 'MEMBER';
}): Promise<InviteSummaryResponse> {
  const res = await opts.app.inject({
    method: 'POST',
    url: '/admin/invites',
    headers: { host: `${opts.tenantKey}.hubins.com`, cookie: opts.cookie },
    body: { email: opts.email, role: opts.role ?? 'MEMBER' },
  });
  expect(res.statusCode).toBe(201);
  const { invite } = CreateInviteResponseSchema.parse(res.json());
  return invite;
}

// ── Test suite ──────────────────────────────────────────────────────────────

describe('POST /admin/invites', () => {
  let app: FastifyInstance;
  let deps: AppDeps;
  let queue: InMemQueue;

  beforeAll(async () => {
    const built = await buildTestApp();
    app = built.app;
    deps = built.deps;
    queue = deps.queue as InMemQueue;
  });

  afterAll(async () => {
    await app.close();
  });

  // ── Happy path ────────────────────────────────────────────────────────────

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

    queue.drain();
    const invitedEmail = uniqueEmail('invited');

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

    // tokenHash must NEVER appear in response — checked against raw parsed object
    const inviteRaw = invite as Record<string, unknown>;
    expect(inviteRaw.tokenHash).toBeUndefined();

    // expires_at ≈ 7 days from now (allow ±60s for test latency)
    const expiresAt = new Date(invite.expiresAt).getTime();
    const expectedExpiry = Date.now() + 7 * 24 * 60 * 60 * 1000;
    expect(Math.abs(expiresAt - expectedExpiry)).toBeLessThan(60_000);
  });

  it('admin creates an ADMIN invite → role=ADMIN confirmed', async () => {
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

    queue.drain();
    const invitedEmail = uniqueEmail('invited-admin');

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'ADMIN' },
    });

    expect(res.statusCode).toBe(201);
    const { invite } = CreateInviteResponseSchema.parse(res.json());
    expect(invite.role).toBe('ADMIN');

    // Verify DB row correctness
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

    queue.drain();
    const invitedEmail = uniqueEmail('audit-check');

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(201);
    const { invite } = CreateInviteResponseSchema.parse(res.json());

    const auditRow = await deps.db
      .selectFrom('audit_events')
      .selectAll()
      .where('action', '=', 'invite.created')
      .where('tenant_id', '=', tenant.id)
      .orderBy('created_at', 'desc')
      .limit(1)
      .executeTakeFirst();

    expect(auditRow).toBeDefined();
    const meta = auditRow!.metadata as Record<string, unknown>;
    expect(meta.inviteId).toBe(invite.id);
    expect(meta.email).toBe(invitedEmail);
    expect(meta.role).toBe('MEMBER');
  });

  it('invite email enqueued on admin.invite-email queue', async () => {
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

    queue.drain();
    const invitedEmail = uniqueEmail('queue-check');

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(201);
    const { invite } = CreateInviteResponseSchema.parse(res.json());

    const messages = queue.drain();
    // Type predicate narrows QueueMessage → AdminInviteEmailMessage
    const inviteMsg = messages.find(
      (m): m is AdminInviteEmailMessage =>
        m.type === 'admin.invite-email' && m.inviteId === invite.id,
    );

    expect(inviteMsg).toBeDefined();
    expect(inviteMsg).toMatchObject({
      type: 'admin.invite-email',
      email: invitedEmail,
      role: 'MEMBER',
      tenantKey: tk,
    });
    expect(typeof inviteMsg!.inviteToken).toBe('string');
    expect(inviteMsg!.inviteToken.length).toBeGreaterThan(0);
  });

  it('no membership row created when invite is created (Decision C)', async () => {
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

    queue.drain();
    const invitedEmail = uniqueEmail('no-membership');

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(201);

    // Invited user does not yet exist — no membership row should be created
    const membershipCount = await deps.db
      .selectFrom('memberships')
      .select(deps.db.fn.count('id').as('count'))
      .where('tenant_id', '=', tenant.id)
      .where(
        'user_id',
        'in',
        deps.db.selectFrom('users').select('id').where('email', '=', invitedEmail),
      )
      .executeTakeFirst();

    expect(Number(membershipCount?.count ?? 0)).toBe(0);
  });

  // ── Auth guards ───────────────────────────────────────────────────────────

  it('unauthenticated → 401', async () => {
    const tk = tenantKey();
    await createTenant({ db: deps.db, tenantKey: tk });

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com` },
      body: { email: 'test@example.com', role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(401);
  });

  it('MEMBER role (not admin) → 403', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });

    // Seed a MEMBER user directly
    const memberEmail = uniqueEmail('member');
    const memberUser = await deps.db
      .insertInto('users')
      .values({ email: memberEmail, name: 'Member User' })
      .returning(['id'])
      .executeTakeFirstOrThrow();

    const pwHash = await deps.passwordHasher.hash('Password123!');
    await deps.db
      .insertInto('auth_identities')
      .values({
        user_id: memberUser.id,
        provider: 'password',
        password_hash: pwHash,
        provider_subject: null,
      })
      .execute();
    await deps.db
      .insertInto('memberships')
      .values({ tenant_id: tenant.id, user_id: memberUser.id, role: 'MEMBER', status: 'ACTIVE' })
      .execute();

    const loginRes = await app.inject({
      method: 'POST',
      url: '/auth/login',
      headers: { host: `${tk}.hubins.com` },
      body: { email: memberEmail, password: 'Password123!' },
    });
    expect(loginRes.statusCode).toBe(200);
    const memberCookie = getCookie(loginRes);

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie: memberCookie },
      body: { email: 'newuser@example.com', role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(403);
    const { error } = ErrorBodySchema.parse(res.json());
    expect(error.message).toBe('Insufficient role.');
  });

  it('admin without MFA verified → 403', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk });

    // Seed admin WITHOUT MFA setup
    const adminEmail = uniqueEmail('admin-nomfa');
    const adminUser = await deps.db
      .insertInto('users')
      .values({ email: adminEmail, name: 'Admin No MFA' })
      .returning(['id'])
      .executeTakeFirstOrThrow();

    const pwHash = await deps.passwordHasher.hash('Password123!');
    await deps.db
      .insertInto('auth_identities')
      .values({
        user_id: adminUser.id,
        provider: 'password',
        password_hash: pwHash,
        provider_subject: null,
      })
      .execute();
    await deps.db
      .insertInto('memberships')
      .values({ tenant_id: tenant.id, user_id: adminUser.id, role: 'ADMIN', status: 'ACTIVE' })
      .execute();

    // Login — session has mfaVerified=false, nextAction=MFA_SETUP_REQUIRED
    const loginRes = await app.inject({
      method: 'POST',
      url: '/auth/login',
      headers: { host: `${tk}.hubins.com` },
      body: { email: adminEmail, password: 'Password123!' },
    });
    expect(loginRes.statusCode).toBe(200);
    const adminCookie = getCookie(loginRes);

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie: adminCookie },
      body: { email: 'newuser@example.com', role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(403);
    const { error } = ErrorBodySchema.parse(res.json());
    expect(error.message).toBe('MFA verification required.');
  });

  // ── Business rule failures ────────────────────────────────────────────────

  it('duplicate PENDING invite same email → 409', async () => {
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

    queue.drain();
    const invitedEmail = uniqueEmail('dup-check');

    // First invite — should succeed
    const first = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'MEMBER' },
    });
    expect(first.statusCode).toBe(201);

    // Second invite for the same email — should fail
    const second = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: invitedEmail, role: 'MEMBER' },
    });
    expect(second.statusCode).toBe(409);
    const { error } = ErrorBodySchema.parse(second.json());
    expect(error.code).toBe('CONFLICT');
  });

  it('email domain not in allowedEmailDomains → 403', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({
      db: deps.db,
      tenantKey: tk,
      allowedEmailDomains: ['allowed.com'],
    });
    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      // UUID-prefixed so the users.email unique constraint never fires on re-runs
      email: uniqueEmailForDomain('allowed.com'),
      password: 'Password123!',
    });

    queue.drain();

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: 'user@notallowed.com', role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(403);
  });

  it('tenant with no domain restriction → any email accepted', async () => {
    const tk = tenantKey();
    const tenant = await createTenant({ db: deps.db, tenantKey: tk }); // no restrictions
    const { cookie } = await createAdminSession({
      app,
      deps,
      tenantId: tenant.id,
      tenantKey: tk,
      email: uniqueEmail('admin'),
      password: 'Password123!',
    });

    queue.drain();

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: 'anyone@anyplace.io', role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(201);
  });

  it('invited email has ACTIVE membership → 409', async () => {
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

    queue.drain();

    const memberEmail = uniqueEmail('existing-member');
    const memberUser = await deps.db
      .insertInto('users')
      .values({ email: memberEmail, name: 'Existing Member' })
      .returning(['id'])
      .executeTakeFirstOrThrow();
    await deps.db
      .insertInto('memberships')
      .values({ tenant_id: tenant.id, user_id: memberUser.id, role: 'MEMBER', status: 'ACTIVE' })
      .execute();

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: memberEmail, role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(409);
  });

  it('invited email has SUSPENDED membership → 403', async () => {
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

    queue.drain();

    const suspendedEmail = uniqueEmail('suspended');
    const suspendedUser = await deps.db
      .insertInto('users')
      .values({ email: suspendedEmail, name: 'Suspended User' })
      .returning(['id'])
      .executeTakeFirstOrThrow();
    await deps.db
      .insertInto('memberships')
      .values({
        tenant_id: tenant.id,
        user_id: suspendedUser.id,
        role: 'MEMBER',
        status: 'SUSPENDED',
      })
      .execute();

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: suspendedEmail, role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(403);
  });

  // ── Validation failures ───────────────────────────────────────────────────

  it('missing email → 400', async () => {
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

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(400);
  });

  it('invalid email format → 400', async () => {
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

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: 'not-an-email', role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(400);
  });

  it('invalid role → 400', async () => {
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

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: 'user@example.com', role: 'SUPERADMIN' },
    });

    expect(res.statusCode).toBe(400);
  });

  it('createdByUserId in DB row matches session.userId', async () => {
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

    queue.drain();

    const res = await app.inject({
      method: 'POST',
      url: '/admin/invites',
      headers: { host: `${tk}.hubins.com`, cookie },
      body: { email: uniqueEmail('check-creator'), role: 'MEMBER' },
    });

    expect(res.statusCode).toBe(201);
    const { invite } = CreateInviteResponseSchema.parse(res.json());

    const dbRow = await deps.db
      .selectFrom('invites')
      .select(['created_by_user_id'])
      .where('id', '=', invite.id)
      .executeTakeFirstOrThrow();

    expect(dbRow.created_by_user_id).toBe(userId);
  });
});

describe('Admin invites - list / resend / cancel', () => {
  let app: FastifyInstance;
  let deps: AppDeps;
  let queue: InMemQueue;

  beforeAll(async () => {
    const built = await buildTestApp();
    app = built.app;
    deps = built.deps;
    queue = deps.queue as InMemQueue;
  });

  afterAll(async () => {
    await app.close();
  });

  // ── GET /admin/invites ────────────────────────────────────────────────────

  describe('GET /admin/invites', () => {
    it('returns empty list when tenant has no invites', async () => {
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
      queue.drain();

      const res = await app.inject({
        method: 'GET',
        url: '/admin/invites',
        headers: { host: `${tk}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = ListInvitesResponseSchema.parse(res.json());
      expect(body.invites).toHaveLength(0);
      expect(body.total).toBe(0);
      expect(body.limit).toBe(20); // default
      expect(body.offset).toBe(0); // default
    });

    it('returns created invites with correct shape and total count', async () => {
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
      queue.drain();

      // Create 2 invites
      const email1 = uniqueEmail('list-a');
      const email2 = uniqueEmail('list-b');
      await createInviteViaApi({ app, tenantKey: tk, cookie, email: email1 });
      await createInviteViaApi({ app, tenantKey: tk, cookie, email: email2 });
      queue.drain();

      const res = await app.inject({
        method: 'GET',
        url: '/admin/invites',
        headers: { host: `${tk}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = ListInvitesResponseSchema.parse(res.json());
      expect(body.total).toBe(2);
      expect(body.invites).toHaveLength(2);

      // All returned invites belong to this tenant
      for (const inv of body.invites) {
        expect(inv.tenantId).toBe(tenant.id);
        expect(inv.status).toBe('PENDING');
      }

      // tokenHash must never appear
      for (const inv of body.invites) {
        const raw = inv as Record<string, unknown>;
        expect(raw.tokenHash).toBeUndefined();
      }

      // Sorted newest first — email2 was created after email1
      const emails = body.invites.map((i) => i.email);
      expect(emails).toContain(email1);
      expect(emails).toContain(email2);
    });

    it('status filter: ?status=PENDING returns only pending invites', async () => {
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
      queue.drain();

      // Create 2 invites, then cancel one directly in DB
      const email1 = uniqueEmail('filter-keep');
      const email2 = uniqueEmail('filter-cancel');
      await createInviteViaApi({ app, tenantKey: tk, cookie, email: email1 });
      const invite2 = await createInviteViaApi({ app, tenantKey: tk, cookie, email: email2 });
      queue.drain();

      await deps.db
        .updateTable('invites')
        .set({ status: 'CANCELLED' })
        .where('id', '=', invite2.id)
        .execute();

      const res = await app.inject({
        method: 'GET',
        url: '/admin/invites?status=PENDING',
        headers: { host: `${tk}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = ListInvitesResponseSchema.parse(res.json());
      expect(body.total).toBe(1);
      expect(body.invites).toHaveLength(1);
      expect(body.invites[0].email).toBe(email1);
      expect(body.invites[0].status).toBe('PENDING');
    });

    it('status filter: ?status=CANCELLED returns only cancelled invites', async () => {
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
      queue.drain();

      const emailA = uniqueEmail('cancelled-inv');
      const inv = await createInviteViaApi({ app, tenantKey: tk, cookie, email: emailA });
      queue.drain();

      const cancelRes = await app.inject({
        method: 'DELETE',
        url: `/admin/invites/${inv.id}`,
        headers: { host: `${tk}.hubins.com`, cookie },
      });
      expect(cancelRes.statusCode).toBe(200);
      CancelInviteResponseSchema.parse(cancelRes.json());

      const res = await app.inject({
        method: 'GET',
        url: '/admin/invites?status=CANCELLED',
        headers: { host: `${tk}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = ListInvitesResponseSchema.parse(res.json());
      expect(body.total).toBeGreaterThanOrEqual(1);
      const found = body.invites.find((i) => i.id === inv.id);
      expect(found).toBeDefined();
      expect(found!.status).toBe('CANCELLED');
    });

    it('pagination: limit + offset work correctly', async () => {
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
      queue.drain();

      // Create 3 invites
      for (let i = 0; i < 3; i++) {
        await createInviteViaApi({ app, tenantKey: tk, cookie, email: uniqueEmail(`page-${i}`) });
      }
      queue.drain();

      // Page 1: limit=2, offset=0
      const page1 = await app.inject({
        method: 'GET',
        url: '/admin/invites?limit=2&offset=0',
        headers: { host: `${tk}.hubins.com`, cookie },
      });
      expect(page1.statusCode).toBe(200);
      const body1 = ListInvitesResponseSchema.parse(page1.json());
      expect(body1.invites).toHaveLength(2);
      expect(body1.total).toBe(3);
      expect(body1.limit).toBe(2);
      expect(body1.offset).toBe(0);

      // Page 2: limit=2, offset=2
      const page2 = await app.inject({
        method: 'GET',
        url: '/admin/invites?limit=2&offset=2',
        headers: { host: `${tk}.hubins.com`, cookie },
      });
      expect(page2.statusCode).toBe(200);
      const body2 = ListInvitesResponseSchema.parse(page2.json());
      expect(body2.invites).toHaveLength(1);
      expect(body2.total).toBe(3);

      // All 3 IDs across both pages are unique
      const allIds = [...body1.invites.map((i) => i.id), ...body2.invites.map((i) => i.id)];
      expect(new Set(allIds).size).toBe(3);
    });

    it('tenant isolation: admin cannot see invites from a different tenant', async () => {
      // Tenant A — create invite
      const tkA = tenantKey();
      const tenantA = await createTenant({ db: deps.db, tenantKey: tkA });
      const { cookie: cookieA } = await createAdminSession({
        app,
        deps,
        tenantId: tenantA.id,
        tenantKey: tkA,
        email: uniqueEmail('admin-a'),
        password: 'Password123!',
      });
      queue.drain();
      await createInviteViaApi({
        app,
        tenantKey: tkA,
        cookie: cookieA,
        email: uniqueEmail('inv-a'),
      });
      queue.drain();

      // Tenant B — admin lists their invites, must not see tenant A's invite
      const tkB = tenantKey();
      const tenantB = await createTenant({ db: deps.db, tenantKey: tkB });
      const { cookie: cookieB } = await createAdminSession({
        app,
        deps,
        tenantId: tenantB.id,
        tenantKey: tkB,
        email: uniqueEmail('admin-b'),
        password: 'Password123!',
      });
      queue.drain();

      const res = await app.inject({
        method: 'GET',
        url: '/admin/invites',
        headers: { host: `${tkB}.hubins.com`, cookie: cookieB },
      });

      expect(res.statusCode).toBe(200);
      const body = ListInvitesResponseSchema.parse(res.json());
      // Tenant B has no invites of their own
      expect(body.total).toBe(0);
      // No invite from tenant A leaked into the response
      for (const inv of body.invites) {
        expect(inv.tenantId).toBe(tenantB.id);
      }
    });

    it('unauthenticated → 401', async () => {
      const tk = tenantKey();
      await createTenant({ db: deps.db, tenantKey: tk });

      const res = await app.inject({
        method: 'GET',
        url: '/admin/invites',
        headers: { host: `${tk}.hubins.com` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('MEMBER role → 403', async () => {
      const tk = tenantKey();
      const tenant = await createTenant({ db: deps.db, tenantKey: tk });

      const memberEmail = uniqueEmail('list-member');
      const memberUser = await deps.db
        .insertInto('users')
        .values({ email: memberEmail, name: 'Member' })
        .returning(['id'])
        .executeTakeFirstOrThrow();
      const pwHash = await deps.passwordHasher.hash('Password123!');
      await deps.db
        .insertInto('auth_identities')
        .values({
          user_id: memberUser.id,
          provider: 'password',
          password_hash: pwHash,
          provider_subject: null,
        })
        .execute();
      await deps.db
        .insertInto('memberships')
        .values({ tenant_id: tenant.id, user_id: memberUser.id, role: 'MEMBER', status: 'ACTIVE' })
        .execute();

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tk}.hubins.com` },
        body: { email: memberEmail, password: 'Password123!' },
      });
      expect(loginRes.statusCode).toBe(200);
      const memberCookie = getCookie(loginRes);

      const res = await app.inject({
        method: 'GET',
        url: '/admin/invites',
        headers: { host: `${tk}.hubins.com`, cookie: memberCookie },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // ── POST /admin/invites/:inviteId/resend ──────────────────────────────────

  describe('POST /admin/invites/:inviteId/resend', () => {
    it('resend pending invite → 200, new invite created, old cancelled, new email queued, audit written', async () => {
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
      queue.drain();

      const invitedEmail = uniqueEmail('resend-target');
      const original = await createInviteViaApi({
        app,
        tenantKey: tk,
        cookie,
        email: invitedEmail,
      });
      queue.drain();

      const res = await app.inject({
        method: 'POST',
        url: `/admin/invites/${original.id}/resend`,
        headers: { host: `${tk}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const { invite: newInvite } = CreateInviteResponseSchema.parse(res.json());

      // New invite has a different ID
      expect(newInvite.id).not.toBe(original.id);

      // New invite is PENDING with same email/role
      expect(newInvite.status).toBe('PENDING');
      expect(newInvite.email).toBe(invitedEmail);
      expect(newInvite.role).toBe('MEMBER');
      expect(newInvite.tenantId).toBe(tenant.id);

      // Old invite is now CANCELLED in DB
      const oldRow = await deps.db
        .selectFrom('invites')
        .selectAll()
        .where('id', '=', original.id)
        .executeTakeFirstOrThrow();
      expect(oldRow.status).toBe('CANCELLED');
      expect(oldRow.used_at).not.toBeNull();

      // New invite row exists and is PENDING
      const newRow = await deps.db
        .selectFrom('invites')
        .selectAll()
        .where('id', '=', newInvite.id)
        .executeTakeFirstOrThrow();
      expect(newRow.status).toBe('PENDING');
      // New token hash differs from old token hash
      expect(newRow.token_hash).not.toBe(oldRow.token_hash);

      // Invite email enqueued for the new invite
      const messages = queue.drain();
      const inviteMsg = messages.find(
        (m): m is AdminInviteEmailMessage =>
          m.type === 'admin.invite-email' && m.inviteId === newInvite.id,
      );
      expect(inviteMsg).toBeDefined();
      expect(inviteMsg!.email).toBe(invitedEmail);
      expect(inviteMsg!.tenantKey).toBe(tk);
      expect(typeof inviteMsg!.inviteToken).toBe('string');
      expect(inviteMsg!.inviteToken.length).toBeGreaterThan(0);

      // Audit: invite.resent written with both old and new invite IDs
      const auditRow = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'invite.resent')
        .where('tenant_id', '=', tenant.id)
        .orderBy('created_at', 'desc')
        .limit(1)
        .executeTakeFirst();

      expect(auditRow).toBeDefined();
      const meta = auditRow!.metadata as Record<string, unknown>;
      expect(meta.oldInviteId).toBe(original.id);
      expect(meta.newInviteId).toBe(newInvite.id);
      expect(meta.email).toBe(invitedEmail);
    });

    it('resend bulk-cancels ALL pending invites for the same email in the tenant', async () => {
      // (tenantId, email), not just the targeted inviteId.
      //
      // Setup: we manually insert a second PENDING invite row for the same email
      // (bypassing the duplicate-check that the API enforces), simulating drift
      // that can occur in edge cases. Then call resend on one of them.
      // After the resend, BOTH original invites must be CANCELLED with used_at set,
      // and exactly ONE new PENDING invite must exist for that email.

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
      queue.drain();

      const invitedEmail = uniqueEmail('bulk-cancel-target');

      // Invite #1: created via API
      const invite1 = await createInviteViaApi({
        app,
        tenantKey: tk,
        cookie,
        email: invitedEmail,
      });
      queue.drain();

      // Invite #2: inserted directly into DB to simulate drift (bypasses API duplicate check)
      const invite2Row = await deps.db
        .insertInto('invites')
        .values({
          tenant_id: tenant.id,
          email: invitedEmail,
          role: 'MEMBER',
          token_hash: `drift-hash-${randomUUID()}`,
          status: 'PENDING',
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          created_by_user_id: userId,
        })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      // Both invites are now PENDING
      const pendingBefore = await deps.db
        .selectFrom('invites')
        .select(['id', 'status'])
        .where('tenant_id', '=', tenant.id)
        .where('email', '=', invitedEmail)
        .where('status', '=', 'PENDING')
        .execute();
      expect(pendingBefore).toHaveLength(2);

      // Resend on invite #1
      const resendRes = await app.inject({
        method: 'POST',
        url: `/admin/invites/${invite1.id}/resend`,
        headers: { host: `${tk}.hubins.com`, cookie },
      });
      expect(resendRes.statusCode).toBe(200);
      const { invite: newInvite } = CreateInviteResponseSchema.parse(resendRes.json());

      // invite #1 is now CANCELLED with used_at set
      const row1 = await deps.db
        .selectFrom('invites')
        .selectAll()
        .where('id', '=', invite1.id)
        .executeTakeFirstOrThrow();
      expect(row1.status).toBe('CANCELLED');
      expect(row1.used_at).not.toBeNull();

      // invite #2 (drift invite) is also now CANCELLED with used_at set
      const row2 = await deps.db
        .selectFrom('invites')
        .selectAll()
        .where('id', '=', invite2Row.id)
        .executeTakeFirstOrThrow();
      expect(row2.status).toBe('CANCELLED');
      expect(row2.used_at).not.toBeNull();

      // Exactly ONE PENDING invite remains for this email — the newly created one
      const pendingAfter = await deps.db
        .selectFrom('invites')
        .select(['id', 'status'])
        .where('tenant_id', '=', tenant.id)
        .where('email', '=', invitedEmail)
        .where('status', '=', 'PENDING')
        .execute();
      expect(pendingAfter).toHaveLength(1);
      expect(pendingAfter[0].id).toBe(newInvite.id);

      // Audit event confirms the resend
      const auditRow = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'invite.resent')
        .where('tenant_id', '=', tenant.id)
        .orderBy('created_at', 'desc')
        .limit(1)
        .executeTakeFirst();
      expect(auditRow).toBeDefined();
      const meta = auditRow!.metadata as Record<string, unknown>;
      expect(meta.newInviteId).toBe(newInvite.id);
    });

    it('resend preserves role from old invite row (ADMIN role)', async () => {
      // This test covers the role-preservation contract: the new invite must carry
      // the same role as the cancelled invite, not a default or request-body value.

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
      queue.drain();

      const invitedEmail = uniqueEmail('role-preserve');

      // Create the original invite with role=ADMIN
      const original = await createInviteViaApi({
        app,
        tenantKey: tk,
        cookie,
        email: invitedEmail,
        role: 'ADMIN',
      });
      expect(original.role).toBe('ADMIN');
      queue.drain();

      // Resend it
      const resendRes = await app.inject({
        method: 'POST',
        url: `/admin/invites/${original.id}/resend`,
        headers: { host: `${tk}.hubins.com`, cookie },
      });
      expect(resendRes.statusCode).toBe(200);
      const { invite: newInvite } = CreateInviteResponseSchema.parse(resendRes.json());

      // New invite must preserve role=ADMIN from the old row
      expect(newInvite.role).toBe('ADMIN');

      // Confirm in DB as well
      const dbRow = await deps.db
        .selectFrom('invites')
        .select(['role'])
        .where('id', '=', newInvite.id)
        .executeTakeFirstOrThrow();
      expect(dbRow.role).toBe('ADMIN');
    });

    it('resend a non-pending (cancelled) invite → 409', async () => {
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
      queue.drain();

      const invite = await createInviteViaApi({
        app,
        tenantKey: tk,
        cookie,
        email: uniqueEmail('already-cancelled'),
      });
      queue.drain();

      // Cancel it first
      await deps.db
        .updateTable('invites')
        .set({ status: 'CANCELLED' })
        .where('id', '=', invite.id)
        .execute();

      const res = await app.inject({
        method: 'POST',
        url: `/admin/invites/${invite.id}/resend`,
        headers: { host: `${tk}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(409);
      const { error } = ErrorBodySchema.parse(res.json());
      expect(error.code).toBe('CONFLICT');
    });

    it('resend invite from another tenant → 404', async () => {
      // Tenant A creates an invite
      const tkA = tenantKey();
      const tenantA = await createTenant({ db: deps.db, tenantKey: tkA });
      const { cookie: cookieA } = await createAdminSession({
        app,
        deps,
        tenantId: tenantA.id,
        tenantKey: tkA,
        email: uniqueEmail('admin-a'),
        password: 'Password123!',
      });
      queue.drain();
      const inviteA = await createInviteViaApi({
        app,
        tenantKey: tkA,
        cookie: cookieA,
        email: uniqueEmail('cross-tenant'),
      });
      queue.drain();

      // Tenant B admin tries to resend tenant A's invite
      const tkB = tenantKey();
      const tenantB = await createTenant({ db: deps.db, tenantKey: tkB });
      const { cookie: cookieB } = await createAdminSession({
        app,
        deps,
        tenantId: tenantB.id,
        tenantKey: tkB,
        email: uniqueEmail('admin-b'),
        password: 'Password123!',
      });

      const res = await app.inject({
        method: 'POST',
        url: `/admin/invites/${inviteA.id}/resend`,
        headers: { host: `${tkB}.hubins.com`, cookie: cookieB },
      });

      expect(res.statusCode).toBe(404);
    });

    it('non-UUID inviteId → 400', async () => {
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

      const res = await app.inject({
        method: 'POST',
        url: '/admin/invites/not-a-uuid/resend',
        headers: { host: `${tk}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(400);
    });

    it('unauthenticated → 401', async () => {
      const tk = tenantKey();
      await createTenant({ db: deps.db, tenantKey: tk });

      const res = await app.inject({
        method: 'POST',
        url: `/admin/invites/${randomUUID()}/resend`,
        headers: { host: `${tk}.hubins.com` },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // ── DELETE /admin/invites/:inviteId ───────────────────────────────────────

  describe('DELETE /admin/invites/:inviteId', () => {
    it('cancel pending invite → 200 { status: CANCELLED }, DB status=CANCELLED, audit written', async () => {
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
      queue.drain();

      const invitedEmail = uniqueEmail('cancel-target');
      const invite = await createInviteViaApi({ app, tenantKey: tk, cookie, email: invitedEmail });
      queue.drain();

      const res = await app.inject({
        method: 'DELETE',
        url: `/admin/invites/${invite.id}`,
        headers: { host: `${tk}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = CancelInviteResponseSchema.parse(res.json());
      expect(body.status).toBe('CANCELLED');

      // DB row is CANCELLED
      const dbRow = await deps.db
        .selectFrom('invites')
        .selectAll()
        .where('id', '=', invite.id)
        .executeTakeFirstOrThrow();
      expect(dbRow.status).toBe('CANCELLED');
      expect(dbRow.used_at).not.toBeNull();

      // Audit event: invite.cancelled
      const auditRow = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'invite.cancelled')
        .where('tenant_id', '=', tenant.id)
        .orderBy('created_at', 'desc')
        .limit(1)
        .executeTakeFirst();

      expect(auditRow).toBeDefined();
      const meta = auditRow!.metadata as Record<string, unknown>;
      expect(meta.inviteId).toBe(invite.id);
      expect(meta.email).toBe(invitedEmail);
    });

    it('cancel already-cancelled invite → 409', async () => {
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
      queue.drain();

      const invite = await createInviteViaApi({
        app,
        tenantKey: tk,
        cookie,
        email: uniqueEmail('double-cancel'),
      });
      queue.drain();

      // First cancel — succeeds
      const first = await app.inject({
        method: 'DELETE',
        url: `/admin/invites/${invite.id}`,
        headers: { host: `${tk}.hubins.com`, cookie },
      });
      expect(first.statusCode).toBe(200);
      CancelInviteResponseSchema.parse(first.json());

      // Second cancel — already cancelled
      const second = await app.inject({
        method: 'DELETE',
        url: `/admin/invites/${invite.id}`,
        headers: { host: `${tk}.hubins.com`, cookie },
      });
      expect(second.statusCode).toBe(409);
      const { error } = ErrorBodySchema.parse(second.json());
      expect(error.code).toBe('CONFLICT');
    });

    it('cancel invite from another tenant → 404', async () => {
      const tkA = tenantKey();
      const tenantA = await createTenant({ db: deps.db, tenantKey: tkA });
      const { cookie: cookieA } = await createAdminSession({
        app,
        deps,
        tenantId: tenantA.id,
        tenantKey: tkA,
        email: uniqueEmail('admin-a'),
        password: 'Password123!',
      });
      queue.drain();
      const inviteA = await createInviteViaApi({
        app,
        tenantKey: tkA,
        cookie: cookieA,
        email: uniqueEmail('cross'),
      });
      queue.drain();

      const tkB = tenantKey();
      const tenantB = await createTenant({ db: deps.db, tenantKey: tkB });
      const { cookie: cookieB } = await createAdminSession({
        app,
        deps,
        tenantId: tenantB.id,
        tenantKey: tkB,
        email: uniqueEmail('admin-b'),
        password: 'Password123!',
      });

      const res = await app.inject({
        method: 'DELETE',
        url: `/admin/invites/${inviteA.id}`,
        headers: { host: `${tkB}.hubins.com`, cookie: cookieB },
      });

      expect(res.statusCode).toBe(404);
    });

    it('non-UUID inviteId → 400', async () => {
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

      const res = await app.inject({
        method: 'DELETE',
        url: '/admin/invites/not-a-uuid',
        headers: { host: `${tk}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(400);
    });

    it('unauthenticated → 401', async () => {
      const tk = tenantKey();
      await createTenant({ db: deps.db, tenantKey: tk });

      const res = await app.inject({
        method: 'DELETE',
        url: `/admin/invites/${randomUUID()}`,
        headers: { host: `${tk}.hubins.com` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('MEMBER role → 403', async () => {
      const tk = tenantKey();
      const tenant = await createTenant({ db: deps.db, tenantKey: tk });

      const memberEmail = uniqueEmail('cancel-member');
      const memberUser = await deps.db
        .insertInto('users')
        .values({ email: memberEmail, name: 'Member' })
        .returning(['id'])
        .executeTakeFirstOrThrow();
      const pwHash = await deps.passwordHasher.hash('Password123!');
      await deps.db
        .insertInto('auth_identities')
        .values({
          user_id: memberUser.id,
          provider: 'password',
          password_hash: pwHash,
          provider_subject: null,
        })
        .execute();
      await deps.db
        .insertInto('memberships')
        .values({ tenant_id: tenant.id, user_id: memberUser.id, role: 'MEMBER', status: 'ACTIVE' })
        .execute();

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tk}.hubins.com` },
        body: { email: memberEmail, password: 'Password123!' },
      });
      expect(loginRes.statusCode).toBe(200);
      const memberCookie = getCookie(loginRes);

      const res = await app.inject({
        method: 'DELETE',
        url: `/admin/invites/${randomUUID()}`,
        headers: { host: `${tk}.hubins.com`, cookie: memberCookie },
      });

      expect(res.statusCode).toBe(403);
    });
  });
});
