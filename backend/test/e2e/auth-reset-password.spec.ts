import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import { getLatestOutboxPayloadForUser } from '../helpers/outbox-test-helpers';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';

/**
 * E2E tests for POST /auth/reset-password (Brick 8).
 *
 * These tests drive the full flow by calling forgot-password first
 * to obtain a raw token (now from Outbox, decrypted in tests),
 * then testing the consume step.
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

/** Triggers forgot-password and returns the raw token from Outbox (decrypted in tests). */
async function obtainResetToken(opts: {
  inject: InjectLike;
  db: DbExecutor;
  outboxEncryption: Awaited<ReturnType<typeof buildTestApp>>['deps']['outboxEncryption'];
  host: string;
  email: string;
  userId: string;
}): Promise<string> {
  await opts.inject({
    method: 'POST',
    url: '/auth/forgot-password',
    headers: { host: opts.host },
    payload: { email: opts.email },
  });

  const outbox = await getLatestOutboxPayloadForUser({
    db: opts.db,
    outboxEncryption: opts.outboxEncryption,
    type: 'password.reset',
    userId: opts.userId,
  });

  return outbox.token;
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
        db,
        outboxEncryption: deps.outboxEncryption,
        host,
        email,
        userId: user.id,
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
      const user = await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password: 'OldPass123!',
      });

      const rawToken = await obtainResetToken({
        inject: app.inject.bind(app),
        db,
        outboxEncryption: deps.outboxEncryption,
        host,
        email,
        userId: user.id,
      });

      const first = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        headers: { host },
        payload: { token: rawToken, newPassword: 'NewPass456!' },
      });
      expect(first.statusCode).toBe(200);

      const second = await app.inject({
        method: 'POST',
        url: '/auth/reset-password',
        headers: { host },
        payload: { token: rawToken, newPassword: 'NewPass789!' },
      });

      expect(second.statusCode).toBe(400);
      const body = readJson<ErrorResponseBody>(second);
      expect(body.error.message).toBeTruthy();
    } finally {
      await close();
    }
  });

  it('same token used concurrently -> exactly one request succeeds', async () => {
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
        db,
        outboxEncryption: deps.outboxEncryption,
        host,
        email,
        userId: user.id,
      });

      const makeReq = (newPassword: string) =>
        app.inject({
          method: 'POST',
          url: '/auth/reset-password',
          headers: { host },
          payload: { token: rawToken, newPassword },
        });

      const [a, b] = await Promise.all([makeReq('RacePassA1!'), makeReq('RacePassB1!')]);
      const codes = [a.statusCode, b.statusCode].sort((x, y) => x - y);

      expect(codes).toEqual([200, 400]);

      const userIdentity = await db
        .selectFrom('auth_identities')
        .select(['password_hash'])
        .where('user_id', '=', user.id)
        .where('provider', '=', 'password')
        .executeTakeFirstOrThrow();

      const matchesA = await passwordHasher.verify('RacePassA1!', userIdentity.password_hash ?? '');
      const matchesB = await passwordHasher.verify('RacePassB1!', userIdentity.password_hash ?? '');

      expect(Number(matchesA) + Number(matchesB)).toBe(1);
    } finally {
      await close();
    }
  });
});
