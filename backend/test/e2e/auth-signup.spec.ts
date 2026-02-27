import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import { getLatestOutboxPayloadForUser } from '../helpers/outbox-test-helpers';
import type { DbExecutor } from '../../src/shared/db/db';

/**
 * E2E tests for POST /auth/signup.
 *
 * Contract:
 * - Only works when tenant.public_signup_enabled = true.
 * - New users always require email verification → nextAction: EMAIL_VERIFICATION_REQUIRED.
 * - Existing users joining a new tenant are already verified → nextAction: NONE.
 * - Admin signup → nextAction: EMAIL_VERIFICATION_REQUIRED (Decision 3: email beats MFA).
 * - All membership conflict states (ACTIVE / INVITED / SUSPENDED) are rejected before
 *   any write happens.
 * - Tenant domain restrictions are enforced.
 * - Rate limits enforced when nodeEnv: 'development'.
 *
 * ISOLATION:
 * - Every test creates its own UUID-keyed tenant and email.
 * - All DB assertions are scoped to user_id or tenant_id.
 * - Audit absences use timestamp-scoped queries (parallel-safe).
 */

type SignupResponseBody = {
  status: 'AUTHENTICATED';
  nextAction: string;
  user: { id: string; email: string; name: string };
  membership: { id: string; role: 'ADMIN' | 'MEMBER' };
};

type ErrorResponseBody = {
  error: { message: string; code?: string };
};

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function extractCookie(res: { headers: Record<string, unknown> }): string {
  const raw = res.headers['set-cookie'];
  if (Array.isArray(raw)) return raw[0] as string;
  return raw as string;
}

async function createSignupTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  allowedDomains?: string[];
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: true,
      member_mfa_required: false,
      allowed_email_domains: sql`${JSON.stringify(opts.allowedDomains ?? [])}::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

describe('POST /auth/signup', () => {
  it('new user → 201, EMAIL_VERIFICATION_REQUIRED, session cookie, verification email enqueued', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `new-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createSignupTenant({ db, tenantKey });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/signup',
        headers: { host },
        payload: {
          email,
          password: 'Password123!',
          name: 'Test User',
        },
      });

      expect(res.statusCode).toBe(201);

      const cookie = extractCookie(res);
      expect(cookie).toContain('sid=');

      const body = readJson<SignupResponseBody>(res);
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('EMAIL_VERIFICATION_REQUIRED');
      expect(body.user.email).toBe(email.toLowerCase());
      expect(body.membership.role).toBe('MEMBER');

      // User created
      const users = await db
        .selectFrom('users')
        .selectAll()
        .where('email', '=', email.toLowerCase())
        .execute();
      expect(users).toHaveLength(1);
      expect(users[0].email_verified).toBe(false);

      // Password identity created
      const identities = await db
        .selectFrom('auth_identities')
        .selectAll()
        .where('user_id', '=', users[0].id)
        .where('provider', '=', 'password')
        .execute();
      expect(identities).toHaveLength(1);

      // Membership created as ACTIVE
      const memberships = await db
        .selectFrom('memberships')
        .selectAll()
        .where('tenant_id', '=', tenant.id)
        .where('user_id', '=', users[0].id)
        .execute();
      expect(memberships).toHaveLength(1);
      expect(memberships[0].status).toBe('ACTIVE');

      // Verification token stored in DB
      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', users[0].id)
        .where('used_at', 'is', null)
        .execute();
      expect(tokens).toHaveLength(1);
      expect(tokens[0].expires_at.getTime()).toBeGreaterThan(Date.now());

      // Verification email is now persisted via Outbox (Step 2)
      const outbox = await getLatestOutboxPayloadForUser({
        db,
        outboxEncryption: deps.outboxEncryption,
        type: 'email.verify',
        userId: users[0].id,
      });

      expect(outbox.toEmail).toBe(email.toLowerCase());
      expect(typeof outbox.token).toBe('string');
      expect(outbox.token.length).toBeGreaterThan(20);
      expect(outbox.idempotencyKey.startsWith(`email-verify:${users[0].id}:`)).toBe(true);

      // Audit events written and scoped to this user + tenant
      const audits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('tenant_id', '=', tenant.id)
        .where('user_id', '=', users[0].id)
        .execute();
      const actions = audits.map((a) => a.action);
      expect(actions).toContain('auth.signup.success');
      expect(actions).toContain('user.created');
      expect(actions).toContain('membership.created');

      // PII hardening: audit events must not contain raw email
      for (const audit of audits) {
        const meta = audit.metadata as Record<string, unknown>;
        expect(meta.email).toBeUndefined();
      }
    } finally {
      await close();
    }
  });

  it('existing verified user (no membership here) → 201, NONE, no verification email, no duplicate identity', async () => {
    // An existing user from another tenant: already has email_verified=true
    // and a password identity. Signing up for a NEW tenant should create only
    // a new membership — no duplicate identity, no verification token/outbox.
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `existing-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      // Pre-create a verified user with a password identity but NO membership
      // for this tenant (simulates a user who registered on another tenant).
      const existingUser = await db
        .insertInto('users')
        .values({ email: email.toLowerCase(), name: 'Existing User' })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const hash = await deps.passwordHasher.hash('SecurePass123!');
      await db
        .insertInto('auth_identities')
        .values({
          user_id: existingUser.id,
          provider: 'password',
          password_hash: hash,
          provider_subject: null,
        })
        .execute();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/signup',
        headers: { host },
        payload: {
          email,
          password: 'Password123!',
          name: 'Existing User',
        },
      });

      expect(res.statusCode).toBe(201);

      const body = readJson<SignupResponseBody>(res);
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE');
      expect(body.user.id).toBe(existingUser.id);

      // No verification token inserted
      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', existingUser.id)
        .execute();
      expect(tokens).toHaveLength(0);

      // No outbox email.verify row for this user
      const outbox = await db
        .selectFrom('outbox_messages')
        .select(['id'])
        .where('type', '=', 'email.verify')
        .where('status', '=', 'pending')
        .where(sql`payload->>'userId'`, '=', existingUser.id)
        .execute();

      expect(outbox).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('domain restriction enforced → 400', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createSignupTenant({ db, tenantKey, allowedDomains: ['good.com'] });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/signup',
        headers: { host },
        payload: {
          email: `bad-${randomUUID().slice(0, 8)}@evil.com`,
          password: 'Password123!',
          name: 'Bad Domain',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toBeTruthy();
    } finally {
      await close();
    }
  });
});
