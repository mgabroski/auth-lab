import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { InMemQueue } from '../../src/shared/messaging/inmem-queue';
import type { SignupVerificationEmailMessage } from '../../src/shared/messaging/queue';

/**
 * E2E tests for POST /auth/resend-verification.
 *
 * Contract:
 * - Requires an authenticated session (401 without one).
 * - Always returns 200 — never reveals rate-limit status or verified state.
 * - If the user is already verified, the endpoint is a silent no-op (no new token, no email).
 * - Each new send invalidates prior active tokens (one-active-at-a-time).
 * - Silent rate limit: 3/email/hour (nodeEnv:'development' required to activate).
 *
 * ISOLATION:
 * - nodeEnv:'development' tests use full-UUID emails (maximally unique keys).
 * - All token/audit assertions are scoped to user_id.
 * - Timestamp-scoped queries used wherever global table counts would be fragile.
 *
 * RATE-LIMIT TEST IP ISOLATION:
 * - buildTestApp({ nodeEnv: 'development' }) enables ALL rate limiters, including
 *   signup's perIp (20/15min). Since Redis is shared across runs, the 127.0.0.1
 *   counter accumulates. The rate-limit test therefore generates a unique fake IP
 *   per run and passes it as `remoteAddress` to every app.inject() call so the
 *   counter always starts from zero.
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
 *
 * Format: 10.x.y.z  (always in RFC-1918 space, never a real routable address)
 */
function uniqueTestIp(): string {
  const hex = randomUUID().replace(/-/g, '');
  const o1 = parseInt(hex.slice(0, 2), 16);
  const o2 = parseInt(hex.slice(2, 4), 16);
  const o3 = parseInt(hex.slice(4, 6), 16);
  return `10.${o1}.${o2}.${o3}`;
}

/**
 * Signs up a new user and returns session cookie + userId.
 * Drains the queue after signup so it's empty for subsequent assertions.
 *
 * @param remoteAddress - Optional IP override. Pass a unique value in
 *   nodeEnv:'development' tests to avoid exhausting the signup perIp counter
 *   on the shared Redis instance across repeated test runs.
 */
async function signupAndDrain(opts: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  queue: InMemQueue;
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
  // Drain signup email so later drain() calls reflect only resend
  opts.queue.drain();

  return { cookie, userId: body.user.id };
}

// ── Tests ─────────────────────────────────────────────────────

describe('POST /auth/resend-verification', () => {
  it('unverified user → 200, new token in DB, verification email enqueued', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, queue } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `resend-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, userId } = await signupAndDrain({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host, cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<ResendResponse>(res);
      expect(body.message).toBeTruthy();

      // New active token in DB for this user
      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .where('used_at', 'is', null)
        .execute();
      expect(tokens).toHaveLength(1);
      expect(tokens[0].expires_at.getTime()).toBeGreaterThan(Date.now());

      // Verification email enqueued with correct fields
      const messages = (queue as InMemQueue).drain<SignupVerificationEmailMessage>();
      expect(messages).toHaveLength(1);
      expect(messages[0].type).toBe('auth.signup-verification-email');
      expect(messages[0].email).toBe(email.toLowerCase());
      expect(messages[0].userId).toBe(userId);
      expect(messages[0].tenantKey).toBe(tenantKey);
      expect(typeof messages[0].verificationToken).toBe('string');
      expect(messages[0].verificationToken.length).toBeGreaterThan(20);
    } finally {
      await close();
    }
  });

  it('resend invalidates previous active token and creates a new one', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, queue, tokenHasher } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `resend-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, userId } = await signupAndDrain({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
      });

      // Capture the original token hash for later comparison
      const originalTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .where('used_at', 'is', null)
        .execute();
      expect(originalTokens).toHaveLength(1);
      const originalHash = originalTokens[0].token_hash;

      // Resend
      const res = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host, cookie },
      });
      expect(res.statusCode).toBe(200);

      const messages = (queue as InMemQueue).drain<SignupVerificationEmailMessage>();
      expect(messages).toHaveLength(1);
      const newHash = tokenHasher.hash(messages[0].verificationToken);

      // New token hash is different from the original
      expect(newHash).not.toBe(originalHash);

      // Only one active token remains (old one invalidated)
      const activeTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .where('used_at', 'is', null)
        .execute();
      expect(activeTokens).toHaveLength(1);

      // Both rows exist: old (used) + new (active)
      const allTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .execute();
      expect(allTokens).toHaveLength(2);

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

  it('already verified user → 200 silent no-op, no new token created', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, queue } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verified-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, userId } = await signupAndDrain({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
      });

      // Manually mark user as verified
      await db
        .updateTable('users')
        .set({ email_verified: true })
        .where('id', '=', userId)
        .execute();

      const requestStart = new Date();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host, cookie },
      });

      // Still 200 — never reveals verified state
      expect(res.statusCode).toBe(200);
      const body = readJson<ResendResponse>(res);
      expect(body.message).toBeTruthy();

      // No new token created after requestStart
      const newTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .where('created_at', '>=', requestStart)
        .execute();
      expect(newTokens).toHaveLength(0);

      // No email enqueued
      const messages = (queue as InMemQueue).drain();
      expect(messages).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('silent rate limit: 4th resend returns 200 but no new token and no email', async () => {
    // Rate limiter is disabled in nodeEnv:'test'. Override to 'development' to activate it.
    // Full UUID email ensures no rate-limit key collision across parallel tests.
    //
    // IP ISOLATION: nodeEnv:'development' also enables signup's perIp rate limit
    // (20/15min). Redis is shared across runs, so 127.0.0.1 accumulates. We
    // generate a unique IP per run and pass it as remoteAddress to every inject
    // call so the signup counter always starts from zero.
    const { app, deps, close } = await buildTestApp({ nodeEnv: 'development' });
    const { db, queue } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `rl-${randomUUID()}@example.com`; // full UUID — maximally unique
    const testIp = uniqueTestIp(); // unique per run — never exhausts shared Redis counter

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, userId } = await signupAndDrain({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
        remoteAddress: testIp,
      });

      // Requests 1–3: within the 3/hour limit — each enqueues an email
      for (let i = 0; i < 3; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/auth/resend-verification',
          headers: { host, cookie },
          remoteAddress: testIp,
        });
        expect(res.statusCode).toBe(200);
        (queue as InMemQueue).drain(); // clear after each to prevent accumulation
      }

      // Request 4: over the limit — silent, still 200
      const requestStart = new Date();
      const res4 = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host, cookie },
        remoteAddress: testIp,
      });
      expect(res4.statusCode).toBe(200);

      // No email enqueued for the 4th request
      const messages = (queue as InMemQueue).drain();
      expect(messages).toHaveLength(0);

      // No new token created at or after requestStart (rate limit blocked the write)
      const newTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .where('created_at', '>=', requestStart)
        .execute();
      expect(newTokens).toHaveLength(0);
    } finally {
      await close();
    }
  });
});
