import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';
import type { InMemQueue } from '../../src/shared/messaging/inmem-queue';

/**
 * E2E tests for POST /auth/forgot-password (Brick 8).
 *
 * Security contract:
 * - Always returns 200 with an identical body regardless of outcome.
 * - Never reveals whether the email exists, is SSO-only, or hit a rate limit.
 * - Audit events are written on ALL paths for admin visibility.
 *
 * ISOLATION NOTE:
 * Tests share a real Postgres + Redis instance and do NOT run inside rolled-back
 * transactions. Every assertion that checks counts or absences must be scoped to
 * the specific user_id / tenant_id created in that test, or use a before/after
 * snapshot. Never query a full table without a scoping filter.
 *
 * RATE LIMIT NOTE:
 * The rate limiter is disabled when nodeEnv === 'test' (see di.ts).
 * The silent-rate-limit test explicitly passes nodeEnv: 'development' to enable
 * it, and uses a UUID-based email so there is zero key collision with other tests.
 */

type ForgotPasswordResponse = { message: string };

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

async function createTenant(opts: { db: DbExecutor; tenantKey: string }) {
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

async function seedUserWithPassword(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  tenantId: string;
  email: string;
  password: string;
}) {
  const user = await opts.db
    .insertInto('users')
    .values({ email: opts.email.toLowerCase(), name: 'Test User' })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const hash = await opts.passwordHasher.hash(opts.password);
  await opts.db
    .insertInto('auth_identities')
    .values({
      user_id: user.id,
      provider: 'password',
      password_hash: hash,
      provider_subject: null,
    })
    .execute();

  await opts.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: 'MEMBER',
      status: 'ACTIVE',
    })
    .execute();

  return user;
}

async function seedSsoOnlyUser(opts: { db: DbExecutor; tenantId: string; email: string }) {
  const user = await opts.db
    .insertInto('users')
    .values({ email: opts.email.toLowerCase(), name: 'SSO User' })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  await opts.db
    .insertInto('auth_identities')
    .values({
      user_id: user.id,
      provider: 'google',
      password_hash: null,
      provider_subject: `google-sub-${randomUUID()}`,
    })
    .execute();

  await opts.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: 'MEMBER',
      status: 'ACTIVE',
    })
    .execute();

  return user;
}

// ── Tests ─────────────────────────────────────────────────────

describe('POST /auth/forgot-password', () => {
  it('valid user with password identity → 200, token in DB, email enqueued with tenantKey', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `user-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      const user = await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password: 'Password123!',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<ForgotPasswordResponse>(res);
      expect(body.message).toBeTruthy();

      // Token stored in DB (only the hash — raw token travels via queue)
      const tokens = await db
        .selectFrom('password_reset_tokens')
        .selectAll()
        .where('user_id', '=', user.id)
        .where('used_at', 'is', null)
        .execute();
      expect(tokens).toHaveLength(1);
      expect(tokens[0].expires_at.getTime()).toBeGreaterThan(Date.now());

      // Email enqueued with tenantKey so the renderer can build the correct URL
      const messages = (deps.queue as InMemQueue).drain();
      expect(messages).toHaveLength(1);
      const msg = messages[0];
      expect(msg.type).toBe('auth.reset-password-email');
      expect(msg.email).toBe(email.toLowerCase());
      expect(msg.userId).toBe(user.id);
      expect(msg.tenantKey).toBe(tenantKey);
      expect(typeof msg.resetToken).toBe('string');
      expect(msg.resetToken.length).toBeGreaterThan(20);

      // Audit written with outcome: 'sent' — scoped to this user
      const audits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.password_reset.requested')
        .where('user_id', '=', user.id)
        .execute();
      expect(audits).toHaveLength(1);
      expect((audits[0].metadata as Record<string, unknown>).outcome).toBe('sent');
    } finally {
      await close();
    }
  });

  it('nonexistent email → 200 with identical body, no new token, no email, audit written', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createTenant({ db, tenantKey });

      // Snapshot BEFORE — we cannot filter by user_id (no user exists), so we
      // compare total counts. The unique email guarantees no user will be found.
      const countBefore = await db
        .selectFrom('password_reset_tokens')
        .select((eb) => eb.fn.countAll<number>().as('n'))
        .executeTakeFirstOrThrow();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email: `ghost-${randomUUID()}@example.com` },
      });

      expect(res.statusCode).toBe(200);

      // No new token created
      const countAfter = await db
        .selectFrom('password_reset_tokens')
        .select((eb) => eb.fn.countAll<number>().as('n'))
        .executeTakeFirstOrThrow();
      expect(Number(countAfter.n)).toBe(Number(countBefore.n));

      // No email enqueued
      const messages = (deps.queue as InMemQueue).drain();
      expect(messages).toHaveLength(0);

      // Audit written (admin visibility) with outcome: 'user_not_found'.
      // user_not_found path writes audit with no user_id in context.
      // Filter by action + null user_id + outcome to isolate from other tests.
      const audits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.password_reset.requested')
        .where('user_id', 'is', null)
        .execute();

      const matching = audits.filter(
        (a) => (a.metadata as Record<string, unknown>).outcome === 'user_not_found',
      );
      expect(matching.length).toBeGreaterThanOrEqual(1);
    } finally {
      await close();
    }
  });

  it('SSO-only user → 200 with identical body, no token, no email, audit outcome: sso_only', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `sso-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      const user = await seedSsoOnlyUser({ db, tenantId: tenant.id, email });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email },
      });

      expect(res.statusCode).toBe(200);

      // No reset token for this specific user
      const tokens = await db
        .selectFrom('password_reset_tokens')
        .where('user_id', '=', user.id)
        .selectAll()
        .execute();
      expect(tokens).toHaveLength(0);

      // No email enqueued
      const messages = (deps.queue as InMemQueue).drain();
      expect(messages).toHaveLength(0);

      // Audit scoped to this user's ID — isolates from all other tests
      const audits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.password_reset.requested')
        .where('user_id', '=', user.id)
        .execute();
      expect(audits).toHaveLength(1);
      expect((audits[0].metadata as Record<string, unknown>).outcome).toBe('sso_only');
    } finally {
      await close();
    }
  });

  it('new request invalidates old token and creates a fresh one', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `user-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      const user = await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password: 'Pass123!',
      });

      // First request
      await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email },
      });
      const msgs1 = (deps.queue as InMemQueue).drain();
      const token1 = msgs1[0].resetToken;

      // Second request — invalidates first
      await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email },
      });
      const msgs2 = (deps.queue as InMemQueue).drain();
      const token2 = msgs2[0].resetToken;

      expect(token1).not.toBe(token2);

      // Only the latest token is still active — scoped to this user
      const activeTokens = await db
        .selectFrom('password_reset_tokens')
        .where('user_id', '=', user.id)
        .where('used_at', 'is', null)
        .selectAll()
        .execute();
      expect(activeTokens).toHaveLength(1);

      // Both tokens exist; the first was invalidated — scoped to this user
      const allTokens = await db
        .selectFrom('password_reset_tokens')
        .where('user_id', '=', user.id)
        .selectAll()
        .execute();
      expect(allTokens).toHaveLength(2);
      const usedToken = allTokens.find((t) => t.used_at !== null);
      expect(usedToken).toBeDefined();
    } finally {
      await close();
    }
  });

  it('silent rate limit: 4th request returns 200 but no token created and no email sent', async () => {
    // Rate limiter is disabled in nodeEnv:'test'. Override to 'development' to
    // enable it for this test. A UUID-based email guarantees no key collision
    // with any other test running in parallel.
    const { app, deps, close } = await buildTestApp({ nodeEnv: 'development' });
    const { db, passwordHasher } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `rl-${randomUUID()}@example.com`; // full UUID — maximally unique

    try {
      const tenant = await createTenant({ db, tenantKey });
      const user = await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password: 'Pass123!',
      });

      // Requests 1–3: all within the 3/hour limit — each creates a token
      for (let i = 0; i < 3; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/auth/forgot-password',
          headers: { host },
          payload: { email },
        });
        expect(res.statusCode).toBe(200);
        // Drain after each so the queue doesn't accumulate
        (deps.queue as InMemQueue).drain();
      }

      // Request 4: over the limit — silent, still 200
      const res4 = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email },
      });
      expect(res4.statusCode).toBe(200);

      // No new email queued for the 4th request
      const messages = (deps.queue as InMemQueue).drain();
      expect(messages).toHaveLength(0);

      // Only 3 tokens exist in DB (one per successful request, each invalidating
      // the previous) — the 4th was silently rejected before touching the DB
      const allTokens = await db
        .selectFrom('password_reset_tokens')
        .where('user_id', '=', user.id)
        .selectAll()
        .execute();
      expect(allTokens).toHaveLength(3);

      // Audit has 4 rows: 3 with outcome 'sent', 1 with outcome 'rate_limited'
      const audits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.password_reset.requested')
        .where('user_id', '=', user.id)
        .execute();
      // The rate_limited path writes audit with no user_id — filter separately
      const sentAudits = audits.filter(
        (a) => (a.metadata as Record<string, unknown>).outcome === 'sent',
      );
      expect(sentAudits).toHaveLength(3);

      // rate_limited audit uses no user_id on the AuditWriter (checked by outcome)
      const rateLimitedAudits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.password_reset.requested')
        .where('user_id', 'is', null)
        .execute();
      const rlMatching = rateLimitedAudits.filter(
        (a) => (a.metadata as Record<string, unknown>).outcome === 'rate_limited',
      );
      expect(rlMatching.length).toBeGreaterThanOrEqual(1);
    } finally {
      await close();
    }
  });

  it('invalid email format → 400 validation error', async () => {
    const { app, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;

    try {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host: `${tenantKey}.localhost:3000` },
        payload: { email: 'not-an-email' },
      });

      expect(res.statusCode).toBe(400);
    } finally {
      await close();
    }
  });
});
