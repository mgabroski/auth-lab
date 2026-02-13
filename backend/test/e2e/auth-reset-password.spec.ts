import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';
import type { InMemQueue } from '../../src/shared/messaging/inmem-queue';
import type { ResetPasswordEmailMessage } from '../../src/shared/messaging/queue';

/**
 * E2E tests for POST /auth/reset-password (Brick 8).
 *
 * These tests drive the full flow by calling forgot-password first
 * to obtain a raw token via the queue, then testing the consume step.
 */

type ResetPasswordResponse = { message: string };
type ErrorResponseBody = { error: { message: string; code?: string } };

type TestApp = Awaited<ReturnType<typeof buildTestApp>>;
type InjectLike = TestApp['app']['inject'];

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

/** Triggers forgot-password and returns the raw token from the in-memory queue. */
async function obtainResetToken(opts: {
  inject: InjectLike;
  queue: InMemQueue;
  host: string;
  email: string;
}): Promise<string> {
  await opts.inject({
    method: 'POST',
    url: '/auth/forgot-password',
    headers: { host: opts.host },
    payload: { email: opts.email },
  });

  const msgs = opts.queue.drain<ResetPasswordEmailMessage>();
  if (!msgs.length) throw new Error('No reset email enqueued — check forgot-password setup');
  return msgs[0].resetToken;
}

describe('POST /auth/reset-password', () => {
  it('valid token → 200, password updated, token consumed, no session cookie set', async () => {
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
        password: 'OldPass123!',
      });

      const rawToken = await obtainResetToken({
        inject: app.inject.bind(app),
        queue: deps.queue as InMemQueue,
        host,
        email,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        headers: { host },
        payload: { token: rawToken, newPassword: 'NewPass456!' },
      });

      expect(res.statusCode).toBe(200);

      const body = readJson<ResetPasswordResponse>(res);
      expect(body.message).toBeTruthy();

      // Token is now consumed
      const tokens = await db
        .selectFrom('password_reset_tokens')
        .where('user_id', '=', user.id)
        .selectAll()
        .execute();
      expect(tokens).toHaveLength(1);
      expect(tokens[0].used_at).not.toBeNull();

      // No session cookie — user must sign in again
      expect(res.headers['set-cookie']).toBeUndefined();

      // Audit written
      const audits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.password_reset.completed')
        .where('user_id', '=', user.id)
        .execute();
      expect(audits).toHaveLength(1);
    } finally {
      await close();
    }
  });

  it('old password rejected, new password accepted after reset', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `user-${randomUUID().slice(0, 8)}@example.com`;
    const oldPassword = 'OldPass123!';
    const newPassword = 'BrandNew789!';

    try {
      const tenant = await createTenant({ db, tenantKey });
      await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password: oldPassword,
      });

      const rawToken = await obtainResetToken({
        inject: app.inject.bind(app),
        queue: deps.queue as InMemQueue,
        host,
        email,
      });

      const resetRes = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        headers: { host },
        payload: { token: rawToken, newPassword },
      });
      expect(resetRes.statusCode).toBe(200);

      // Old password → 401
      const oldLoginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password: oldPassword },
      });
      expect(oldLoginRes.statusCode).toBe(401);

      // New password → 200
      const newLoginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password: newPassword },
      });
      expect(newLoginRes.statusCode).toBe(200);
    } finally {
      await close();
    }
  });

  it('active session before reset is destroyed — session store no longer has it', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `user-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password: 'OldPass123!',
      });

      // Log in to create a session
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password: 'OldPass123!' },
      });

      expect(loginRes.statusCode).toBe(200);

      const setCookieHeader = loginRes.headers['set-cookie'];
      expect(typeof setCookieHeader).toBe('string');

      const sessionCookie = setCookieHeader as string;

      // Reset password
      const rawToken = await obtainResetToken({
        inject: app.inject.bind(app),
        queue: deps.queue as InMemQueue,
        host,
        email,
      });

      await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        headers: { host },
        payload: { token: rawToken, newPassword: 'NewPass456!' },
      });

      // Extract the session ID from "<cookieName>=<sessionId>; ..."
      const cookiePair = sessionCookie.split(';')[0];
      const sessionId = cookiePair?.split('=')[1];

      if (sessionId) {
        const sessionData = await deps.sessionStore.get(sessionId);
        expect(sessionData).toBeNull();
      }
    } finally {
      await close();
    }
  });

  it('expired token → 400 with single vague error message', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher, tokenHasher } = deps;
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

      // Insert an already-expired token manually
      const rawToken = generateFakeToken();
      const tokenHash = tokenHasher.hash(rawToken);

      await db
        .insertInto('password_reset_tokens')
        .values({
          user_id: user.id,
          token_hash: tokenHash,
          expires_at: new Date(Date.now() - 1000), // expired
        })
        .execute();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        headers: { host },
        payload: { token: rawToken, newPassword: 'NewPass456!' },
      });

      expect(res.statusCode).toBe(400);

      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toContain('invalid or has expired');
    } finally {
      await close();
    }
  });

  it('already-used token → 400', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `user-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password: 'OldPass123!',
      });

      const rawToken = await obtainResetToken({
        inject: app.inject.bind(app),
        queue: deps.queue as InMemQueue,
        host,
        email,
      });

      // Use once — success
      const first = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        headers: { host },
        payload: { token: rawToken, newPassword: 'NewPass456!' },
      });
      expect(first.statusCode).toBe(200);

      // Try to reuse — must fail
      const second = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        headers: { host },
        payload: { token: rawToken, newPassword: 'AnotherPass789!' },
      });
      expect(second.statusCode).toBe(400);
    } finally {
      await close();
    }
  });

  it('completely unknown token → 400 with identical vague error', async () => {
    const { app, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;

    try {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        headers: { host: `${tenantKey}.localhost:3000` },
        payload: {
          token: generateFakeToken(),
          newPassword: 'NewPass456!',
        },
      });

      expect(res.statusCode).toBe(400);

      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toContain('invalid or has expired');
    } finally {
      await close();
    }
  });

  it('new password too short → 400 Zod validation error', async () => {
    const { app, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;

    try {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        headers: { host: `${tenantKey}.localhost:3000` },
        payload: {
          token: generateFakeToken(),
          newPassword: 'short',
        },
      });

      expect(res.statusCode).toBe(400);
    } finally {
      await close();
    }
  });
});

// ── Helpers ──────────────────────────────────────────────────

/** Generates a fake token that passes Zod min-length but won't exist in DB. */
function generateFakeToken(): string {
  return `fake_reset_token_${randomUUID()}_${randomUUID()}`;
}
