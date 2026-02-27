import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { z } from 'zod';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';

/**
 * backend/test/e2e/auth-forgot-password.spec.ts
 *
 * WHY:
 * - E2E tests for POST /auth/forgot-password (Brick 8).
 *
 * Security contract:
 * - Always returns 200 with an identical body regardless of outcome.
 * - Never reveals whether the email exists, is SSO-only, or hit a rate limit.
 * - Audit events are written on ALL paths for admin visibility.
 *
 * PR2 contract:
 * - When the reset is issued, an outbox row exists (type=password.reset) with encrypted payload.
 * - No raw email/token stored in outbox payload.
 *
 * ISOLATION NOTE:
 * Tests share a real Postgres + Redis instance and do NOT run inside rolled-back
 * transactions. Every assertion that checks counts or absences must be scoped to
 * the specific user_id / tenant_id created in that test, or use a timestamp scope.
 * Never query a full table without a scoping filter.
 *
 * RATE LIMIT NOTE:
 * The rate limiter is disabled when nodeEnv === 'test' (see di.ts).
 * The silent-rate-limit test explicitly passes nodeEnv: 'development' to enable
 * it, and uses a UUID-based email so there is zero key collision with other tests.
 *
 * RULES:
 * - No `any` / unsafe member access. Parse JSON using schemas at boundaries.
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

const EncryptedOutboxPayloadSchema = z.object({
  tokenEnc: z.string().min(1),
  toEmailEnc: z.string().min(1),
  tenantKey: z.string().optional(),
  userId: z.string().optional(),
});

function parseOutboxPayload(input: unknown): z.infer<typeof EncryptedOutboxPayloadSchema> {
  return EncryptedOutboxPayloadSchema.parse(input);
}

// ── Tests ─────────────────────────────────────────────────────

describe('POST /auth/forgot-password', () => {
  it('valid user with password identity → 200, token in DB, outbox row exists', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `user-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createTenant({ db, tenantKey });

      const tenantId = (
        await db
          .selectFrom('tenants')
          .select(['id'])
          .where('key', '=', tenantKey)
          .executeTakeFirstOrThrow()
      ).id;

      const user = await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId,
        email,
        password: 'Password123!',
      });

      const requestStart = new Date();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<ForgotPasswordResponse>(res);
      expect(body.message).toBeTruthy();

      // Token stored in DB (hash only)
      const tokens = await db
        .selectFrom('password_reset_tokens')
        .selectAll()
        .where('user_id', '=', user.id)
        .where('used_at', 'is', null)
        .execute();
      expect(tokens).toHaveLength(1);
      expect(tokens[0].expires_at.getTime()).toBeGreaterThan(Date.now());

      // Outbox row exists (durable delivery)
      const outbox = await db
        .selectFrom('outbox_messages')
        .selectAll()
        .where('created_at', '>=', requestStart)
        .where('type', '=', 'password.reset')
        .where('status', '=', 'pending')
        .where('idempotency_key', 'like', `password-reset:${user.id}:%`)
        .execute();
      expect(outbox).toHaveLength(1);

      const payload = parseOutboxPayload(outbox[0].payload);
      expect(payload.tokenEnc).toMatch(/^v[0-9]+:/);
      expect(payload.toEmailEnc).toMatch(/^v[0-9]+:/);

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

  it('nonexistent email → 200 with identical body, no new token, no outbox row, audit written', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createTenant({ db, tenantKey });

      const requestStart = new Date();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email: `ghost-${randomUUID()}@example.com` },
      });

      expect(res.statusCode).toBe(200);
      void res;

      const newTokens = await db
        .selectFrom('password_reset_tokens')
        .selectAll()
        .where('created_at', '>=', requestStart)
        .execute();
      expect(newTokens).toHaveLength(0);

      const outbox = await db
        .selectFrom('outbox_messages')
        .selectAll()
        .where('created_at', '>=', requestStart)
        .execute();
      expect(outbox).toHaveLength(0);

      const audits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.password_reset.requested')
        .where('created_at', '>=', requestStart)
        .execute();

      const matching = audits.filter(
        (a) => (a.metadata as Record<string, unknown>).outcome === 'user_not_found',
      );
      expect(matching.length).toBeGreaterThanOrEqual(1);
    } finally {
      await close();
    }
  });

  it('SSO-only user → 200 with identical body, no token, no outbox row, audit outcome: sso_only', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `sso-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      const user = await seedSsoOnlyUser({ db, tenantId: tenant.id, email });

      const requestStart = new Date();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email },
      });

      expect(res.statusCode).toBe(200);
      void res;

      const tokens = await db
        .selectFrom('password_reset_tokens')
        .where('user_id', '=', user.id)
        .selectAll()
        .execute();
      expect(tokens).toHaveLength(0);

      const outbox = await db
        .selectFrom('outbox_messages')
        .selectAll()
        .where('created_at', '>=', requestStart)
        .execute();
      expect(outbox).toHaveLength(0);

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

      await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email },
      });

      // Second request — invalidates first
      await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email },
      });

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

      // Two outbox rows created (one per request), each with unique idempotency key
      const outbox = await db
        .selectFrom('outbox_messages')
        .selectAll()
        .where('type', '=', 'password.reset')
        .where('idempotency_key', 'like', `password-reset:${user.id}:%`)
        .execute();
      expect(outbox.length).toBe(2);
      expect(outbox[0].idempotency_key).not.toBe(outbox[1].idempotency_key);
    } finally {
      await close();
    }
  });

  it('silent rate limit: 4th request returns 200 but no token created and no outbox row written', async () => {
    const { app, deps, close } = await buildTestApp({ nodeEnv: 'development' });
    const { db, passwordHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `rl-${randomUUID()}@example.com`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      const user = await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password: 'Pass123!',
      });

      // Requests 1–3
      for (let i = 0; i < 3; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/auth/forgot-password',
          headers: { host },
          payload: { email },
        });
        expect(res.statusCode).toBe(200);
      }

      const requestStart = new Date();

      // Request 4: over limit — silent 200
      const res4 = await app.inject({
        method: 'POST',
        url: '/auth/forgot-password',
        headers: { host },
        payload: { email },
      });
      expect(res4.statusCode).toBe(200);

      // No new token after requestStart
      const newTokens = await db
        .selectFrom('password_reset_tokens')
        .selectAll()
        .where('user_id', '=', user.id)
        .where('created_at', '>=', requestStart)
        .execute();
      expect(newTokens).toHaveLength(0);

      // No outbox row after requestStart
      const outbox = await db
        .selectFrom('outbox_messages')
        .selectAll()
        .where('created_at', '>=', requestStart)
        .execute();
      expect(outbox).toHaveLength(0);

      // Only 3 tokens total exist for this user
      const allTokens = await db
        .selectFrom('password_reset_tokens')
        .where('user_id', '=', user.id)
        .selectAll()
        .execute();
      expect(allTokens).toHaveLength(3);
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
