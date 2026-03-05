import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import { getLatestOutboxPayloadForUser } from '../helpers/outbox-test-helpers';
import type { DbExecutor } from '../../src/shared/db/db';
import type { OutboxEncryption } from '../../src/shared/outbox/outbox-encryption';
import { SESSION_COOKIE_NAME } from '../../src/shared/session/session.types';

/**
 * E2E tests for POST /auth/verify-email.
 *
 * Contract:
 * - Requires an authenticated session (401 without one).
 * - Consumes the verification token atomically (used_at set in same tx as email_verified flip).
 * - Ownership-checked: a token belonging to another user is rejected as invalid.
 * - Idempotent: already-verified user with a VALID UNUSED token → 200 (token consumed, no error).
 * - Single error message for all invalid token states (expired / used / wrong) — no oracle.
 * - Upgrades the existing server-side session in Redis so emailVerified becomes true.
 *   The cookie value does NOT change (no logout/login needed).
 * - Rate limited: 10/IP/15min — prevents brute-forcing verification tokens.
 *
 * SETUP PATTERN:
 * - Most tests sign up first to get a real session cookie + raw token (now from Outbox, decrypted in tests).
 *
 * RATE-LIMIT TEST IP ISOLATION:
 * - buildTestApp({ nodeEnv: 'development' }) enables ALL rate limiters, including
 *   signup's perIp (20/15min). Since Redis is shared across runs, the 127.0.0.1
 *   counter accumulates. The rate-limit test therefore generates a unique fake IP
 *   per run and passes it as `remoteAddress` to every app.inject() call so both
 *   the signup counter and the verify-email counter always start from zero.
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

function extractSessionId(cookieHeader: string): string {
  // cookieHeader example: "sid=<uuid>; Path=/; HttpOnly; SameSite=Strict"
  const first = cookieHeader.split(';')[0];
  const [name, value] = first.split('=');
  if (name !== SESSION_COOKIE_NAME || !value) {
    throw new Error(`Unexpected cookie header: ${cookieHeader}`);
  }
  return value;
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

async function signupAndGetToken(opts: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  db: DbExecutor;
  outboxEncryption: OutboxEncryption;
  tenantKey: string;
  email: string;
  remoteAddress?: string;
}): Promise<{ cookie: string; verificationToken: string; userId: string }> {
  const res = await opts.app.inject({
    method: 'POST',
    url: '/auth/signup',
    headers: { host: `${opts.tenantKey}.localhost:3000` },
    payload: {
      email: opts.email,
      password: 'Password123!',
      name: 'Test User',
    },
    remoteAddress: opts.remoteAddress,
  });

  expect(res.statusCode).toBe(201);

  const cookie = extractCookie(res);
  const body = readJson<{ user: { id: string } }>(res);

  const outbox = await getLatestOutboxPayloadForUser({
    db: opts.db,
    outboxEncryption: opts.outboxEncryption,
    type: 'email.verify',
    userId: body.user.id,
  });

  return { cookie, verificationToken: outbox.token, userId: body.user.id };
}

describe('POST /auth/verify-email', () => {
  it('valid token → 200 VERIFIED, email_verified=true in DB, token consumed, audit written', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, verificationToken, userId } = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email,
      });

      const sessionId = extractSessionId(cookie);
      const sessionBefore = await deps.sessionStore.get(sessionId);
      expect(sessionBefore).not.toBeNull();
      expect(sessionBefore?.emailVerified).toBe(false);

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

      // verify-email must not rotate session cookie
      expect(res.headers['set-cookie']).toBeUndefined();

      const userAfter = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', userId)
        .executeTakeFirstOrThrow();
      expect(userAfter.email_verified).toBe(true);

      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .execute();
      expect(tokens).toHaveLength(1);
      expect(tokens[0].used_at).not.toBeNull();

      const audits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('user_id', '=', userId)
        .where('action', '=', 'auth.email.verified')
        .execute();
      expect(audits).toHaveLength(1);

      // Stage 3: the existing session is upgraded in Redis.
      const sessionAfter = await deps.sessionStore.get(sessionId);
      expect(sessionAfter).not.toBeNull();
      expect(sessionAfter?.emailVerified).toBe(true);
    } finally {
      await close();
    }
  });

  it('invalid (unknown) token → 400', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, userId } = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: 'not-a-real-token' },
      });

      expect(res.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toBeTruthy();

      const userAfter = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', userId)
        .executeTakeFirstOrThrow();
      expect(userAfter.email_verified).toBe(false);
    } finally {
      await close();
    }
  });

  it('expired token → 400', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, verificationToken, userId } = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email,
      });

      await db
        .updateTable('email_verification_tokens')
        .set({ expires_at: new Date(Date.now() - 60_000) })
        .where('user_id', '=', userId)
        .execute();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });

      expect(res.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toBeTruthy();
    } finally {
      await close();
    }
  });

  it('already-used token → 400', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, verificationToken } = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email,
      });

      const first = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });
      expect(first.statusCode).toBe(200);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });

      expect(res.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toBeTruthy();
    } finally {
      await close();
    }
  });

  it('token belonging to a different user → 400 (ownership check)', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createSignupTenant({ db, tenantKey });

      const emailA = `a-${randomUUID().slice(0, 8)}@example.com`;
      const emailB = `b-${randomUUID().slice(0, 8)}@example.com`;

      const { verificationToken: tokenA, userId: userA } = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email: emailA,
      });

      const { cookie: cookieB, userId: userB } = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email: emailB,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie: cookieB },
        payload: { token: tokenA },
      });

      expect(res.statusCode).toBe(400);

      const aAfter = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', userA)
        .executeTakeFirstOrThrow();
      const bAfter = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', userB)
        .executeTakeFirstOrThrow();
      expect(aAfter.email_verified).toBe(false);
      expect(bAfter.email_verified).toBe(false);

      const tokensA = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userA)
        .execute();
      expect(tokensA).toHaveLength(1);
      expect(tokensA[0].used_at).toBeNull();
    } finally {
      await close();
    }
  });

  it('idempotent: already-verified user with valid token → 200 (token consumed, no error)', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      // Create a user + UNUSED valid token via signup
      const { cookie, verificationToken, userId } = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email,
      });

      // Simulate "already verified" user state WITHOUT consuming the token.
      // This matches the contract: a valid token may still exist even though user is verified.
      await db
        .updateTable('users')
        .set({ email_verified: true })
        .where('id', '=', userId)
        .execute();

      const second = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });

      expect(second.statusCode).toBe(200);
      const body = readJson<VerifyEmailResponse>(second);
      expect(body.status).toBe('VERIFIED');

      // Token consumed
      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', userId)
        .execute();
      expect(tokens).toHaveLength(1);
      expect(tokens[0].used_at).not.toBeNull();
    } finally {
      await close();
    }
  });

  it('token too short → 400 validation error', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie } = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
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
      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toBeTruthy();
    } finally {
      await close();
    }
  });

  it('rate limit: 11th verify attempt from same IP → 429', async () => {
    const { app, deps, close } = await buildTestApp({ nodeEnv: 'development' });
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;
    const remoteAddress = `203.0.113.${Math.floor(Math.random() * 200) + 1}`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie, verificationToken } = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email,
        remoteAddress,
      });

      for (let i = 0; i < 10; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/auth/verify-email',
          headers: { host, cookie },
          payload: { token: verificationToken },
          remoteAddress,
        });
        expect([200, 400]).toContain(res.statusCode);
      }

      const last = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
        remoteAddress,
      });

      expect(last.statusCode).toBe(429);
    } finally {
      await close();
    }
  });
});
