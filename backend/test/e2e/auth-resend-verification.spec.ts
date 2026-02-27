import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { z } from 'zod';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';

/**
 * backend/test/e2e/auth-resend-verification.spec.ts
 *
 * WHY:
 * - E2E coverage for POST /auth/resend-verification.
 * - Ensures silent semantics (no oracle) + token invalidation rules.
 * - PR2: confirms durable outbox row is created with encrypted payload.
 *
 * RULES:
 * - No `any` / unsafe member access. Parse JSON using schemas at boundaries.
 * - Scoping: assert rows by user_id / created_at. Never assume empty tables.
 * - Rate limiter is disabled in nodeEnv:'test'; enable explicitly for rate-limit tests.
 */

type ResendResponse = { message: string };

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function extractCookie(res: { headers: Record<string, unknown> }): string {
  const raw = res.headers['set-cookie'];
  if (Array.isArray(raw)) return raw[0] as string;
  return raw as string;
}

async function createSignupTenant(opts: { db: DbExecutor; tenantKey: string }) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: true,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

/**
 * Build a unique fake IP address from a UUID.
 * Used only in nodeEnv:'development' tests so each run starts with a fresh
 * Redis counter and never inherits counts from prior runs or parallel workers.
 */
function uniqueTestIp(): string {
  const hex = randomUUID().replace(/-/g, '');
  const o1 = parseInt(hex.slice(0, 2), 16);
  const o2 = parseInt(hex.slice(2, 4), 16);
  const o3 = parseInt(hex.slice(4, 6), 16);
  return `10.${o1}.${o2}.${o3}`;
}

async function signup(opts: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  tenantKey: string;
  email: string;
  password?: string;
  remoteAddress?: string;
}): Promise<{ cookie: string; userId: string }> {
  const res = await opts.app.inject({
    method: 'POST',
    url: '/auth/signup',
    headers: { host: `${opts.tenantKey}.localhost:3000` },
    remoteAddress: opts.remoteAddress,
    payload: {
      email: opts.email,
      password: opts.password ?? 'SecurePass123!',
      name: 'Test User',
    },
  });

  expect(res.statusCode).toBe(201);

  const cookie = extractCookie(res);
  const body = readJson<{ user: { id: string } }>(res);

  return { cookie, userId: body.user.id };
}

// ── Typed payload parsing to satisfy eslint rules ────────────────────────────

const EncryptedOutboxPayloadSchema = z.object({
  tokenEnc: z.string().min(1),
  toEmailEnc: z.string().min(1),
  tenantKey: z.string().optional(),
  userId: z.string().optional(),
});

function parseOutboxPayload(input: unknown): z.infer<typeof EncryptedOutboxPayloadSchema> {
  return EncryptedOutboxPayloadSchema.parse(input);
}

describe('POST /auth/resend-verification', () => {
  it('unverified user → 200, new token in DB, outbox row exists', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `resend-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, userId } = await signup({ app, tenantKey, email });

      const requestStart = new Date();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<ResendResponse>(res);
      expect(body.message).toBeTruthy();

      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .where('used_at', 'is', null)
        .execute();
      expect(tokens).toHaveLength(1);

      const outbox = await db
        .selectFrom('outbox_messages')
        .selectAll()
        .where('created_at', '>=', requestStart)
        .where('type', '=', 'email.verify')
        .where('status', '=', 'pending')
        .where('idempotency_key', 'like', `email-verify-resend:${userId}:%`)
        .execute();
      expect(outbox).toHaveLength(1);

      const payload = parseOutboxPayload(outbox[0].payload);
      expect(payload.tokenEnc).toMatch(/^v[0-9]+:/);
      expect(payload.toEmailEnc).toMatch(/^v[0-9]+:/);
    } finally {
      await close();
    }
  });

  it('resend invalidates previous active token and creates a new one', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `resend-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, userId } = await signup({ app, tenantKey, email });

      const originalTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .where('used_at', 'is', null)
        .execute();
      expect(originalTokens).toHaveLength(1);
      const originalHash = originalTokens[0].token_hash;

      const res = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host, cookie },
      });
      expect(res.statusCode).toBe(200);

      const activeTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .where('used_at', 'is', null)
        .execute();
      expect(activeTokens).toHaveLength(1);
      expect(activeTokens[0].token_hash).not.toBe(originalHash);

      const allTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .execute();
      expect(allTokens.length).toBe(2);

      const invalidated = allTokens.find((t) => t.token_hash === originalHash);
      expect(invalidated?.used_at).not.toBeNull();
    } finally {
      await close();
    }
  });

  it('no session → 401', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;

    try {
      await createSignupTenant({ db, tenantKey });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host: `${tenantKey}.localhost:3000` },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await close();
    }
  });

  it('already verified user → 200 silent no-op, no new token created and no outbox row written', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verified-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createSignupTenant({ db, tenantKey });

      // ✅ no "as any": email_verified is a boolean column, insert a boolean.
      const user = await db
        .insertInto('users')
        .values({ email: email.toLowerCase(), name: 'Verified', email_verified: true })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const membership = await db
        .insertInto('memberships')
        .values({
          tenant_id: tenant.id,
          user_id: user.id,
          role: 'MEMBER',
          status: 'ACTIVE',
        })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const sessionId = await deps.sessionStore.create({
        userId: user.id,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        membershipId: membership.id,
        role: 'MEMBER',
        mfaVerified: false,
        createdAt: new Date().toISOString(),
      });

      const requestStart = new Date();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host, cookie: `sid=${sessionId}` },
      });

      expect(res.statusCode).toBe(200);

      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', user.id)
        .execute();
      expect(tokens).toHaveLength(0);

      const outbox = await db
        .selectFrom('outbox_messages')
        .selectAll()
        .where('created_at', '>=', requestStart)
        .execute();
      expect(outbox).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('silent rate limit: 4th request returns 200 but no token created and no outbox row written', async () => {
    const ip = uniqueTestIp();
    const { app, deps, close } = await buildTestApp({ nodeEnv: 'development' });
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `rl-${randomUUID()}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, userId } = await signup({ app, tenantKey, email, remoteAddress: ip });

      for (let i = 0; i < 3; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/auth/resend-verification',
          headers: { host, cookie },
          remoteAddress: ip,
        });
        expect(res.statusCode).toBe(200);
      }

      const requestStart = new Date();

      const res4 = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host, cookie },
        remoteAddress: ip,
      });
      expect(res4.statusCode).toBe(200);

      const newTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .where('created_at', '>=', requestStart)
        .execute();
      expect(newTokens).toHaveLength(0);

      const outbox = await db
        .selectFrom('outbox_messages')
        .selectAll()
        .where('created_at', '>=', requestStart)
        .execute();
      expect(outbox).toHaveLength(0);
    } finally {
      await close();
    }
  });
});
