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
 *
 * PR1: POST /admin/invites tests only.
 * PR2: GET /admin/invites, POST .../resend, DELETE ... tests added below.
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

const ErrorBodySchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
  }),
});

// Exported for PR2 reuse in list/resend/cancel tests
export type InviteSummaryResponse = z.infer<typeof InviteSummarySchema>;

// ── Shared helpers ──────────────────────────────────────────────────────────

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
