import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { InMemQueue } from '../../src/shared/messaging/inmem-queue';
import type { SignupVerificationEmailMessage } from '../../src/shared/messaging/queue';

/**
 * E2E tests for POST /auth/verify-email.
 *
 * Contract:
 * - Requires an authenticated session (401 without one).
 * - Consumes the verification token atomically (used_at set in same tx as email_verified flip).
 * - Ownership-checked: a token belonging to another user is rejected as invalid.
 * - Idempotent: a valid token for an already-verified user is consumed without error.
 * - Single error message for all invalid token states (expired / used / wrong) — no oracle.
 * - Does NOT modify the session — caller keeps their existing cookie.
 *
 * SETUP PATTERN:
 * - Most tests sign up first to get a real session cookie + raw token from the queue.
 * - Targeted negative tests (expired, already-used) seed tokens directly for precision.
 *
 * ISOLATION:
 * - Every test creates its own UUID-keyed tenant and email.
 * - DB assertions are always scoped to user_id.
 */

type VerifyEmailResponse = { status: 'VERIFIED' };
type ErrorResponseBody = { error: { message: string; code?: string } };

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
 * Signs up a new user and returns the session cookie + raw verification token.
 * The token is obtained from the in-memory queue immediately after signup.
 */
async function signupAndGetToken(opts: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  queue: InMemQueue;
  tenantKey: string;
  email: string;
  password?: string;
  name?: string;
}): Promise<{ cookie: string; verificationToken: string; userId: string }> {
  const res = await opts.app.inject({
    method: 'POST',
    url: '/auth/signup',
    headers: { host: `${opts.tenantKey}.localhost:3000` },
    payload: {
      email: opts.email,
      password: opts.password ?? 'SecurePass123!',
      name: opts.name ?? 'Test User',
    },
  });

  expect(res.statusCode).toBe(201);

  const cookie = extractCookie(res);
  const body = readJson<{ user: { id: string } }>(res);

  const messages = opts.queue.drain<SignupVerificationEmailMessage>();
  expect(messages).toHaveLength(1);
  const verificationToken = messages[0].verificationToken;

  return { cookie, verificationToken, userId: body.user.id };
}

// ── Tests ─────────────────────────────────────────────────────

describe('POST /auth/verify-email', () => {
  it('valid token → 200 VERIFIED, email_verified=true in DB, token consumed, audit written', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, queue } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, verificationToken, userId } = await signupAndGetToken({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
      });

      // Confirm still unverified before calling endpoint
      const userBefore = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', userId)
        .executeTakeFirstOrThrow();
      expect(userBefore.email_verified).toBe(false);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<VerifyEmailResponse>(res);
      expect(body.status).toBe('VERIFIED');

      // email_verified flipped in DB
      const userAfter = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', userId)
        .executeTakeFirstOrThrow();
      expect(userAfter.email_verified).toBe(true);

      // Token consumed (used_at set)
      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .execute();
      expect(tokens).toHaveLength(1);
      expect(tokens[0].used_at).not.toBeNull();

      // Audit event written
      const audits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('user_id', '=', userId)
        .where('action', '=', 'auth.email.verified')
        .execute();
      expect(audits).toHaveLength(1);
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
        url: '/auth/verify-email',
        headers: { host: `${tenantKey}.localhost:3000` },
        payload: { token: `tok_${randomUUID()}_${randomUUID()}` },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await close();
    }
  });

  it('invalid (unknown) token → 400', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, queue } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      // Sign up to get a valid session — then use a completely fake token
      const { cookie } = await signupAndGetToken({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: `fake_${randomUUID()}_${randomUUID()}` },
      });

      expect(res.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message.toLowerCase()).toContain('invalid');
    } finally {
      await close();
    }
  });

  it('expired token → 400', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, queue, tokenHasher } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      // Sign up to get session + auto-created token
      const { cookie, userId } = await signupAndGetToken({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
      });

      // Backdate the existing token to simulate expiry
      await db
        .updateTable('email_verification_tokens')
        .set({ expires_at: new Date(Date.now() - 1000) })
        .where('user_id', '=', userId)
        .where('used_at', 'is', null)
        .execute();

      // Insert a new raw token whose hash we know, also expired
      const rawToken = `exp_${randomUUID()}_${randomUUID()}`;
      const tokenHash = tokenHasher.hash(rawToken);
      await db
        .insertInto('email_verification_tokens')
        .values({
          user_id: userId,
          token_hash: tokenHash,
          expires_at: new Date(Date.now() - 1000), // already expired
        })
        .execute();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: rawToken },
      });

      expect(res.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message.toLowerCase()).toContain('invalid');
    } finally {
      await close();
    }
  });

  it('already-used token → 400', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, queue } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, verificationToken } = await signupAndGetToken({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
      });

      // First consumption → success
      const res1 = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });
      expect(res1.statusCode).toBe(200);

      // Second consumption → 400 (token already used)
      const res2 = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });
      expect(res2.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(res2);
      expect(body.error.message.toLowerCase()).toContain('invalid');
    } finally {
      await close();
    }
  });

  it('token belonging to a different user → 400 (ownership check)', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, queue } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const emailA = `userA-${randomUUID().slice(0, 8)}@example.com`;
    const emailB = `userB-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      // User A signs up — grab session cookie
      const { cookie: cookieA } = await signupAndGetToken({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email: emailA,
      });

      // User B signs up — grab their verification token
      const { verificationToken: tokenB } = await signupAndGetToken({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email: emailB,
      });

      // User A tries to use User B's token → ownership mismatch → 400
      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie: cookieA },
        payload: { token: tokenB },
      });

      expect(res.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message.toLowerCase()).toContain('invalid');
    } finally {
      await close();
    }
  });

  it('idempotent: already-verified user with valid token → 200 (token consumed, no error)', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, queue } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `idem-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, verificationToken, userId } = await signupAndGetToken({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
      });

      // First verify — success
      const res1 = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });
      expect(res1.statusCode).toBe(200);

      // Manually insert a fresh unused token for same user (simulates edge case)
      const rawToken2 = `tok2_${randomUUID()}_${randomUUID()}`;
      const tokenHash2 = deps.tokenHasher.hash(rawToken2);
      await db
        .insertInto('email_verification_tokens')
        .values({
          user_id: userId,
          token_hash: tokenHash2,
          expires_at: new Date(Date.now() + 3600_000),
        })
        .execute();

      // Second verify with new token for already-verified user → idempotent 200
      const res2 = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: rawToken2 },
      });

      expect(res2.statusCode).toBe(200);
      const body = readJson<VerifyEmailResponse>(res2);
      expect(body.status).toBe('VERIFIED');
    } finally {
      await close();
    }
  });

  it('token too short → 400 validation error', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, queue } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `val-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie } = await signupAndGetToken({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: 'short' },
      });

      expect(res.statusCode).toBe(400);
    } finally {
      await close();
    }
  });
});
