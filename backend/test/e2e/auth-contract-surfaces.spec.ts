import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import { getLatestOutboxPayloadForUser } from '../helpers/outbox-test-helpers';
import type { DbExecutor } from '../../src/shared/db/db';
import type { OutboxEncryption } from '../../src/shared/outbox/outbox-encryption';
import {
  SESSION_COOKIE_NAME,
  SESSION_USER_INDEX_PREFIX,
} from '../../src/shared/session/session.types';

/**
 * test/e2e/auth-contract-surfaces.spec.ts
 *
 * PURPOSE:
 * Dedicated regression suite that locks the auth module's contract surfaces so
 * future refactors cannot silently break security/behavior guarantees.
 */

type ErrorBody = {
  error: {
    message: string;
    code?: string;
  };
};

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function extractCookie(res: { headers: Record<string, unknown> }): string {
  const raw = res.headers['set-cookie'];
  if (Array.isArray(raw)) return raw[0] as string;
  return raw as string;
}

function extractSessionId(cookieHeader: string): string {
  const first = cookieHeader.split(';')[0];
  const [name, value] = first.split('=');
  if (name !== SESSION_COOKIE_NAME || !value) {
    throw new Error(`Unexpected cookie header: ${cookieHeader}`);
  }
  return value;
}

async function createTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  isActive: boolean;
  publicSignupEnabled: boolean;
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: opts.isActive,
      public_signup_enabled: opts.publicSignupEnabled,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

async function signupAndGetVerificationToken(opts: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  db: DbExecutor;
  outboxEncryption: OutboxEncryption;
  tenantKey: string;
  email: string;
}): Promise<{ cookie: string; verificationToken: string; userId: string; sessionId: string }> {
  const res = await opts.app.inject({
    method: 'POST',
    url: '/auth/signup',
    headers: { host: `${opts.tenantKey}.localhost:3000` },
    payload: {
      email: opts.email,
      password: 'Password123!',
      name: 'Test User',
    },
  });

  expect(res.statusCode).toBe(201);

  const cookie = extractCookie(res);
  const sessionId = extractSessionId(cookie);
  const body = readJson<{ user: { id: string } }>(res);

  const outbox = await getLatestOutboxPayloadForUser({
    db: opts.db,
    outboxEncryption: opts.outboxEncryption,
    type: 'email.verify',
    userId: body.user.id,
  });

  return { cookie, verificationToken: outbox.token, userId: body.user.id, sessionId };
}

describe('Auth contract surfaces (regression suite)', () => {
  it('Admin endpoints require email verification (session/authContext enforced)', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createTenant({
        db: deps.db,
        tenantKey,
        isActive: true,
        publicSignupEnabled: false,
      });

      const sessionId = await deps.sessionStore.create({
        userId: randomUUID(),
        tenantId: tenant.id,
        tenantKey,
        membershipId: randomUUID(),
        role: 'ADMIN',
        mfaVerified: true,
        emailVerified: false,
        createdAt: new Date().toISOString(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit-events',
        headers: { host, cookie: `${SESSION_COOKIE_NAME}=${sessionId}` },
      });

      expect(res.statusCode).toBe(403);
      const body = readJson<ErrorBody>(res);
      expect(body.error.message).toBe('Email verification required.');
    } finally {
      await close();
    }
  });

  it('POST /auth/verify-email upgrades the existing Redis session in-place', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `verify-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey,
        isActive: true,
        publicSignupEnabled: true,
      });

      const { cookie, verificationToken, sessionId } = await signupAndGetVerificationToken({
        app,
        db: deps.db,
        outboxEncryption: deps.outboxEncryption,
        tenantKey,
        email,
      });

      const before = await deps.sessionStore.get(sessionId);
      expect(before?.emailVerified).toBe(false);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });

      expect(res.statusCode).toBe(200);

      const after = await deps.sessionStore.get(sessionId);
      expect(after).not.toBeNull();
      expect(after?.emailVerified).toBe(true);
    } finally {
      await close();
    }
  });

  it('Redis session user-index key material does not embed raw userId (uses hashed identifier)', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const userId = randomUUID();
      const tenantId = randomUUID();
      const tenantKey = `t-${randomUUID().slice(0, 8)}`;

      const sessionId = await deps.sessionStore.create({
        userId,
        tenantId,
        tenantKey,
        membershipId: randomUUID(),
        role: 'MEMBER',
        mfaVerified: false,
        emailVerified: true,
        createdAt: new Date().toISOString(),
      });

      const rawIndexKey = `${SESSION_USER_INDEX_PREFIX}:${userId}`;
      const hashedIndexKey = `${SESSION_USER_INDEX_PREFIX}:${deps.tokenHasher.hash(userId)}`;

      const rawMembers = await deps.cache.smembers(rawIndexKey);
      expect(rawMembers).toEqual([]);

      const hashedMembers = await deps.cache.smembers(hashedIndexKey);
      expect(hashedMembers).toContain(sessionId);

      await deps.sessionStore.destroy(sessionId);
    } finally {
      await close();
    }
  });
});

describe('Workspace unavailable — identical response for all three conditions (X5 regression)', () => {
  const EXPECTED_MESSAGE = 'This workspace is not available.';
  const EXPECTED_STATUS = 404;

  it('unknown tenantKey → 404 + contract message', async () => {
    const { app, close } = await buildTestApp();
    try {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: 'does-not-exist-xyz123.localhost:3000' },
        payload: { email: 'a@b.com', password: 'wrongpassword' },
      });

      expect(res.statusCode).toBe(EXPECTED_STATUS);
      expect(readJson<ErrorBody>(res).error.message).toBe(EXPECTED_MESSAGE);
    } finally {
      await close();
    }
  });

  it('known but inactive tenant → same 404 + same message', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `inactive-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey,
        isActive: false,
        publicSignupEnabled: false,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.localhost:3000` },
        payload: { email: 'a@b.com', password: 'wrongpassword' },
      });

      expect(res.statusCode).toBe(EXPECTED_STATUS);
      expect(readJson<ErrorBody>(res).error.message).toBe(EXPECTED_MESSAGE);
    } finally {
      await close();
    }
  });

  it('bare host (no tenant key in subdomain) → same 404 + same message', async () => {
    const { app, close } = await buildTestApp();
    try {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: 'localhost' },
        payload: { email: 'a@b.com', password: 'wrongpassword' },
      });

      expect(res.statusCode).toBe(EXPECTED_STATUS);
      expect(readJson<ErrorBody>(res).error.message).toBe(EXPECTED_MESSAGE);
    } finally {
      await close();
    }
  });

  it('all three conditions are byte-identical on status + error.message (no oracle)', async () => {
    const { app, deps, close } = await buildTestApp();
    const inactiveTenantKey = `inactive2-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey: inactiveTenantKey,
        isActive: false,
        publicSignupEnabled: false,
      });

      const payload = { email: 'a@b.com', password: 'x' };

      const [unknown, inactive, bare] = await Promise.all([
        app.inject({
          method: 'POST',
          url: '/auth/login',
          headers: { host: 'no-such-tenant-xyz.localhost:3000' },
          payload,
        }),
        app.inject({
          method: 'POST',
          url: '/auth/login',
          headers: { host: `${inactiveTenantKey}.localhost:3000` },
          payload,
        }),
        app.inject({
          method: 'POST',
          url: '/auth/login',
          headers: { host: 'localhost' },
          payload,
        }),
      ]);

      expect(unknown.statusCode).toBe(EXPECTED_STATUS);
      expect(inactive.statusCode).toBe(EXPECTED_STATUS);
      expect(bare.statusCode).toBe(EXPECTED_STATUS);

      const unknownMsg = readJson<ErrorBody>(unknown).error.message;
      const inactiveMsg = readJson<ErrorBody>(inactive).error.message;
      const bareMsg = readJson<ErrorBody>(bare).error.message;

      expect(unknownMsg).toBe(EXPECTED_MESSAGE);
      expect(inactiveMsg).toBe(EXPECTED_MESSAGE);
      expect(bareMsg).toBe(EXPECTED_MESSAGE);
      expect(unknownMsg).toBe(inactiveMsg);
      expect(inactiveMsg).toBe(bareMsg);
    } finally {
      await close();
    }
  });
});

describe('Login lockout message (X6 regression)', () => {
  it('6 wrong login attempts → 429 with exact provisioning spec copy', async () => {
    const { app, deps, close } = await buildTestApp({ nodeEnv: 'development' });
    const tenantKey = `lockout-${randomUUID().slice(0, 8)}`;
    const email = `lockout-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'CorrectPassword123!';
    const wrongPassword = 'WrongPassword!';
    const remoteAddress = `10.0.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 200)}`;

    try {
      const tenant = await createTenant({
        db: deps.db,
        tenantKey,
        isActive: true,
        publicSignupEnabled: false,
      });

      const user = await deps.db
        .insertInto('users')
        .values({ email: email.toLowerCase(), name: 'Lockout Test', email_verified: true })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const passwordHash = await deps.passwordHasher.hash(password);
      await deps.db
        .insertInto('auth_identities')
        .values({
          user_id: user.id,
          provider: 'password',
          password_hash: passwordHash,
          provider_subject: null,
        })
        .execute();

      await deps.db
        .insertInto('memberships')
        .values({ tenant_id: tenant.id, user_id: user.id, role: 'MEMBER', status: 'ACTIVE' })
        .execute();

      const host = `${tenantKey}.localhost:3000`;

      for (let i = 0; i < 5; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/auth/login',
          headers: { host },
          payload: { email, password: wrongPassword },
          remoteAddress,
        });
        expect(res.statusCode).toBe(401);
      }

      const lastRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password: wrongPassword },
        remoteAddress,
      });

      expect(lastRes.statusCode).toBe(429);
      expect(readJson<ErrorBody>(lastRes).error.message).toBe(
        'Too many failed attempts. Try again in 15 minutes.',
      );
    } finally {
      await close();
    }
  });
});

describe('MFA verify-setup rate limit (X2 regression)', () => {
  it('6 wrong codes to verify-setup → 429', async () => {
    const { app, deps, close } = await buildTestApp({ nodeEnv: 'development' });
    const tenantKey = `rl-mfa-${randomUUID().slice(0, 8)}`;
    const email = `rl-mfa-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'Password123!';
    const remoteAddress = `10.1.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 200)}`;

    try {
      const tenant = await createTenant({
        db: deps.db,
        tenantKey,
        isActive: true,
        publicSignupEnabled: false,
      });

      const user = await deps.db
        .insertInto('users')
        .values({ email: email.toLowerCase(), name: 'MFA RL Test', email_verified: true })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const passwordHash = await deps.passwordHasher.hash(password);
      await deps.db
        .insertInto('auth_identities')
        .values({
          user_id: user.id,
          provider: 'password',
          password_hash: passwordHash,
          provider_subject: null,
        })
        .execute();

      await deps.db
        .insertInto('memberships')
        .values({ tenant_id: tenant.id, user_id: user.id, role: 'ADMIN', status: 'ACTIVE' })
        .execute();

      const host = `${tenantKey}.localhost:3000`;

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
        remoteAddress,
      });
      expect(loginRes.statusCode).toBe(200);
      const cookie = extractCookie(loginRes);

      const setupRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/setup',
        headers: { host, cookie },
      });
      expect(setupRes.statusCode).toBe(200);

      for (let i = 0; i < 5; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/auth/mfa/verify-setup',
          headers: { host, cookie },
          payload: { code: '000000' },
        });
        expect(res.statusCode).toBe(401);
      }

      const lastRes = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify-setup',
        headers: { host, cookie },
        payload: { code: '000000' },
      });

      expect(lastRes.statusCode).toBe(429);
    } finally {
      await close();
    }
  });
});

describe('TOTP replay prevention (A3 regression)', () => {
  it('same TOTP code submitted twice to /auth/mfa/verify → second is rejected', async () => {
    const { app, deps, cryptoHelpers, close } = await buildTestApp();
    const tenantKey = `replay-${randomUUID().slice(0, 8)}`;
    const email = `replay-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({
        db: deps.db,
        tenantKey,
        isActive: true,
        publicSignupEnabled: false,
      });

      const user = await deps.db
        .insertInto('users')
        .values({ email: email.toLowerCase(), name: 'Replay Test', email_verified: true })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      await deps.db
        .insertInto('auth_identities')
        .values({
          user_id: user.id,
          provider: 'password',
          password_hash: await deps.passwordHasher.hash('irrelevant'),
          provider_subject: null,
        })
        .execute();

      const membership = await deps.db
        .insertInto('memberships')
        .values({ tenant_id: tenant.id, user_id: user.id, role: 'ADMIN', status: 'ACTIVE' })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const plaintextSecret = cryptoHelpers.generateTotpSecret();
      const encryptedSecret = cryptoHelpers.encryptSecret(plaintextSecret);

      await deps.db
        .insertInto('mfa_secrets')
        .values({
          user_id: user.id,
          encrypted_secret: encryptedSecret,
          is_verified: true,
          verified_at: new Date(),
        })
        .execute();

      const sessionId = await deps.sessionStore.create({
        userId: user.id,
        tenantId: tenant.id,
        tenantKey,
        membershipId: membership.id,
        role: 'ADMIN',
        mfaVerified: false,
        emailVerified: true,
        createdAt: new Date().toISOString(),
      });
      const cookie = `${SESSION_COOKIE_NAME}=${sessionId}`;
      const host = `${tenantKey}.localhost:3000`;

      const validCode = cryptoHelpers.generateTotpCode(plaintextSecret);

      const first = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host, cookie },
        payload: { code: validCode },
      });
      expect(first.statusCode).toBe(200);

      const sessionIdB = await deps.sessionStore.create({
        userId: user.id,
        tenantId: tenant.id,
        tenantKey,
        membershipId: membership.id,
        role: 'ADMIN',
        mfaVerified: false,
        emailVerified: true,
        createdAt: new Date().toISOString(),
      });
      const cookieB = `${SESSION_COOKIE_NAME}=${sessionIdB}`;

      const second = await app.inject({
        method: 'POST',
        url: '/auth/mfa/verify',
        headers: { host, cookie: cookieB },
        payload: { code: validCode },
      });

      expect(second.statusCode).not.toBe(200);
      expect([401, 422, 403]).toContain(second.statusCode);
    } finally {
      await close();
    }
  });
});
