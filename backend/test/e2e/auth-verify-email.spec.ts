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
 * - Rate limited: 10/IP/15min — prevents brute-forcing verification tokens.
 * - Decision 3 regression: login for an unverified user returns
 *   EMAIL_VERIFICATION_REQUIRED, never MFA_SETUP_REQUIRED first.
 *
 * SETUP PATTERN:
 * - Most tests sign up first to get a real session cookie + raw token from the queue.
 * - Targeted negative tests (expired, already-used) seed tokens directly for precision.
 *
 * ISOLATION:
 * - Every test creates its own UUID-keyed tenant and email.
 * - DB assertions are always scoped to user_id.
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
 * Signs up a new user and returns the session cookie + raw verification token.
 * The token is obtained from the in-memory queue immediately after signup.
 *
 * @param remoteAddress - Optional IP override. Pass a unique value in
 *   nodeEnv:'development' tests to avoid exhausting the signup perIp counter
 *   on the shared Redis instance across repeated test runs.
 */
async function signupAndGetToken(opts: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  queue: InMemQueue;
  tenantKey: string;
  email: string;
  password?: string;
  name?: string;
  remoteAddress?: string;
}): Promise<{ cookie: string; verificationToken: string; userId: string }> {
  const res = await opts.app.inject({
    method: 'POST',
    url: '/auth/signup',
    headers: { host: `${opts.tenantKey}.localhost:3000` },
    remoteAddress: opts.remoteAddress,
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

  it('rate limit: 11th verify attempt from same IP → 429', async () => {
    // Rate limiter is disabled in nodeEnv:'test'. Override to 'development'.
    // A single user signs up once; all 11 verify attempts reuse the same session
    // and submit a fresh fake token each time (intentional 400s — we only care
    // that the IP counter reaches the limit and the 11th returns 429).
    //
    // IP ISOLATION: nodeEnv:'development' also enables signup's perIp rate limit
    // (20/15min). Redis is shared across runs, so 127.0.0.1 accumulates. We
    // generate a unique IP per run and pass it as remoteAddress to every inject
    // call so both the signup counter and the verify-email counter always start
    // from zero.
    const { app, deps, close } = await buildTestApp({ nodeEnv: 'development' });
    const { db, queue } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `rl-verify-${randomUUID()}@example.com`; // full UUID
    const testIp = uniqueTestIp(); // unique per run — never exhausts shared Redis counter

    try {
      await createSignupTenant({ db, tenantKey });

      const { cookie } = await signupAndGetToken({
        app,
        queue: queue as InMemQueue,
        tenantKey,
        email,
        remoteAddress: testIp,
      });

      // Attempts 1–10: each returns 400 (fake token) but increments the IP counter
      for (let i = 0; i < 10; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/auth/verify-email',
          headers: { host, cookie },
          remoteAddress: testIp,
          payload: { token: `fake_${randomUUID()}_${randomUUID()}` },
        });
        // Each attempt is rejected as invalid token (400), not rate-limited yet
        expect(res.statusCode).toBe(400);
      }

      // 11th attempt: IP counter exceeded → 429
      const res11 = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        remoteAddress: testIp,
        payload: { token: `fake_${randomUUID()}_${randomUUID()}` },
      });

      expect(res11.statusCode).toBe(429);
    } finally {
      await close();
    }
  });

  it('Decision 3 regression: login for unverified user returns EMAIL_VERIFICATION_REQUIRED (not MFA_SETUP_REQUIRED)', async () => {
    // This is a regression guard for the patch applied to execute-login-flow.ts.
    // Without the Decision 3 patch, an unverified admin would see MFA_SETUP_REQUIRED.
    // With the patch, EMAIL_VERIFICATION_REQUIRED must always win.
    //
    // Setup: seed an unverified ADMIN user with password identity + ACTIVE membership.
    // Then call POST /auth/login and assert the nextAction is EMAIL_VERIFICATION_REQUIRED.
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `d3-regression-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'SecurePass123!';

    try {
      const tenant = await db
        .insertInto('tenants')
        .values({
          key: tenantKey,
          name: `Tenant ${tenantKey}`,
          is_active: true,
          public_signup_enabled: false,
          member_mfa_required: false,
          allowed_email_domains: sql`'[]'::jsonb`,
        })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      // Unverified ADMIN user
      const user = await db
        .insertInto('users')
        .values({
          email: email.toLowerCase(),
          name: 'Unverified Admin',
          email_verified: false,
        })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const hash = await deps.passwordHasher.hash(password);
      await db
        .insertInto('auth_identities')
        .values({
          user_id: user.id,
          provider: 'password',
          password_hash: hash,
          provider_subject: null,
        })
        .execute();

      await db
        .insertInto('memberships')
        .values({
          tenant_id: tenant.id,
          user_id: user.id,
          role: 'ADMIN',
          status: 'ACTIVE',
        })
        .execute();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<{ nextAction: string }>(res);

      // Decision 3 must win: email check before MFA check
      expect(body.nextAction).toBe('EMAIL_VERIFICATION_REQUIRED');

      // Explicitly guard against the pre-patch behavior
      expect(body.nextAction).not.toBe('MFA_SETUP_REQUIRED');
      expect(body.nextAction).not.toBe('MFA_REQUIRED');
      expect(body.nextAction).not.toBe('NONE');
    } finally {
      await close();
    }
  });
});
