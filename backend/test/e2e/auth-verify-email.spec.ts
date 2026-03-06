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

      const second = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });

      expect(second.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(second);
      expect(body.error.message).toBeTruthy();
    } finally {
      await close();
    }
  });

  it('token belonging to another user → 400 (ownership check, no oracle)', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;

    const emailA = `verify-a-${randomUUID().slice(0, 8)}@example.com`;
    const emailB = `verify-b-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const a = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email: emailA,
      });

      const b = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email: emailB,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie: a.cookie },
        payload: { token: b.verificationToken },
      });

      expect(res.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toBeTruthy();

      const userA = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', a.userId)
        .executeTakeFirstOrThrow();
      expect(userA.email_verified).toBe(false);

      const userB = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', b.userId)
        .executeTakeFirstOrThrow();
      expect(userB.email_verified).toBe(false);
    } finally {
      await close();
    }
  });

  it('already-verified user with a fresh valid token → 200 (idempotent success) and token consumed', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const first = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email,
      });

      const verifyFirst = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie: first.cookie },
        payload: { token: first.verificationToken },
      });
      expect(verifyFirst.statusCode).toBe(200);

      const freshRawToken = `verify-${randomUUID()}-${randomUUID()}`;
      const freshTokenHash = deps.tokenHasher.hash(freshRawToken);

      await db
        .insertInto('email_verification_tokens')
        .values({
          user_id: first.userId,
          token_hash: freshTokenHash,
          expires_at: new Date(Date.now() + 1000 * 60 * 60),
          used_at: null,
        })
        .execute();

      const secondVerify = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie: first.cookie },
        payload: { token: freshRawToken },
      });

      expect(secondVerify.statusCode).toBe(200);
      const body = readJson<VerifyEmailResponse>(secondVerify);
      expect(body.status).toBe('VERIFIED');

      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', first.userId)
        .orderBy('created_at asc')
        .execute();

      expect(tokens.length).toBeGreaterThanOrEqual(2);
      expect(tokens[tokens.length - 1].used_at).not.toBeNull();
    } finally {
      await close();
    }
  });

  it('session upgrade failure after commit -> still returns 200 and DB state is correct', async () => {
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

      const originalUpdateSession = deps.sessionStore.updateSession.bind(deps.sessionStore);
      deps.sessionStore.updateSession = () => {
        throw new Error('redis_write_failed');
      };

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<VerifyEmailResponse>(res);
      expect(body.status).toBe('VERIFIED');

      const userAfter = await db
        .selectFrom('users')
        .selectAll()
        .where('id', '=', userId)
        .executeTakeFirstOrThrow();
      expect(userAfter.email_verified).toBe(true);

      deps.sessionStore.updateSession = originalUpdateSession;
    } finally {
      await close();
    }
  });

  it('requires authentication (401 without cookie)', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSignupTenant({ db, tenantKey });

      const { verificationToken } = await signupAndGetToken({
        app,
        db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host },
        payload: { token: verificationToken },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await close();
    }
  });
});
