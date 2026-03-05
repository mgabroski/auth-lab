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
 * Dedicated regression suite that locks the auth module’s contract surfaces so
 * future refactors cannot silently break security/behavior guarantees.
 *
 * CONTRACT SURFACES LOCKED HERE:
 *  - Admin endpoints enforce email verification using session/authContext.
 *  - POST /auth/verify-email upgrades the existing Redis session in-place
 *    (emailVerified becomes true for that session; no logout/login required).
 *  - Redis infra keys never embed raw stable identifiers (e.g., userId) in key material.
 *
 * NOTE:
 * - This suite intentionally focuses on high-risk, easy-to-regress behaviors.
 * - SSO crypto verification is covered by unit tests (jose mocking) and existing
 *   E2E flows via FakeSsoAdapter.
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
  // cookieHeader example: "sid=<uuid>; Path=/; HttpOnly; SameSite=Strict"
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

      // Create a session that otherwise satisfies ADMIN+MFA, but is NOT email verified.
      // The route must block before any DB access.
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

      // Sanity: session starts unverified (signup requires verification).
      const before = await deps.sessionStore.get(sessionId);
      expect(before?.emailVerified).toBe(false);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify-email',
        headers: { host, cookie },
        payload: { token: verificationToken },
      });

      expect(res.statusCode).toBe(200);

      // Upgrade happens in-place for the same sessionId.
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

      // Cleanup to avoid cross-test bleed (best-effort).
      await deps.sessionStore.destroy(sessionId);
    } finally {
      await close();
    }
  });
});
