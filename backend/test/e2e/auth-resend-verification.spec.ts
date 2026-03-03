import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import { getLatestOutboxPayloadForUser } from '../helpers/outbox-test-helpers';
import type { DbExecutor } from '../../src/shared/db/db';
/**
 * E2E tests for POST /auth/resend-verification (Brick 11).
 */

type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
  };
};

function extractCookie(res: { headers: Record<string, unknown> }): string {
  // 1. Cast the specific header to what we expect it to be (string | string[] | undefined)
  const raw = res.headers['set-cookie'] as string | string[] | undefined;

  // 2. Determine the single string value
  const cookie = Array.isArray(raw) ? raw[0] : raw;

  // 3. Instead of 'as string', use a hard assertion that Vitest provides
  // This narrows the type to 'string' for the return statement
  expect(typeof cookie).toBe('string');

  return cookie as string;
}

async function createTenant(opts: { db: DbExecutor; tenantKey: string }) {
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

async function signup(opts: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  tenantKey: string;
  email: string;
  password: string;
}) {
  const res = await opts.app.inject({
    method: 'POST',
    url: '/auth/signup',
    headers: { host: `${opts.tenantKey}.hubins.com` },
    body: { email: opts.email, password: opts.password, name: 'Test User' },
  });
  expect(res.statusCode).toBe(201);

  const cookie = extractCookie(res);
  return { cookie };
}

describe('POST /auth/resend-verification', () => {
  it('unverified user → 200, new token in DB, outbox row exists', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `tenant-${randomUUID()}`;
    const email = `user-${randomUUID()}@example.com`;
    const password = 'Password123!';

    try {
      await createTenant({ db, tenantKey });

      const { cookie } = await signup({ app, tenantKey, email, password });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });

      expect(res.statusCode).toBe(200);

      const user = await db
        .selectFrom('users')
        .selectAll()
        .where('email', '=', email.toLowerCase())
        .executeTakeFirstOrThrow();

      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', user.id)
        .where('used_at', 'is', null)
        .execute();

      expect(tokens.length).toBeGreaterThanOrEqual(1);

      // Outbox row exists (type must match OutboxMessageType union)
      const outboxPayload = await getLatestOutboxPayloadForUser({
        db,
        outboxEncryption: deps.outboxEncryption,
        userId: user.id,
        type: 'email.verify',
      });
      expect(outboxPayload).toBeTruthy();
    } finally {
      await close();
    }
  });

  it('resend invalidates previous active token and creates a new one', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `tenant-${randomUUID()}`;
    const email = `user-${randomUUID()}@example.com`;
    const password = 'Password123!';

    try {
      await createTenant({ db, tenantKey });
      const { cookie } = await signup({ app, tenantKey, email, password });

      const user = await db
        .selectFrom('users')
        .selectAll()
        .where('email', '=', email.toLowerCase())
        .executeTakeFirstOrThrow();

      const originalTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', user.id)
        .where('used_at', 'is', null)
        .execute();
      expect(originalTokens).toHaveLength(1);
      const originalHash = originalTokens[0].token_hash;

      const res = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
      });
      expect(res.statusCode).toBe(200);

      const updatedOriginal = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('token_hash', '=', originalHash)
        .executeTakeFirstOrThrow();
      expect(updatedOriginal.used_at).not.toBeNull();

      const newTokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', user.id)
        .where('used_at', 'is', null)
        .execute();
      expect(newTokens).toHaveLength(1);
      expect(newTokens[0].token_hash).not.toBe(originalHash);
    } finally {
      await close();
    }
  });

  it('missing session cookie → 401', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `tenant-${randomUUID()}`;

    try {
      await createTenant({ db, tenantKey });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/resend-verification',
        headers: { host: `${tenantKey}.hubins.com` },
      });

      expect(res.statusCode).toBe(401);
      const body = res.json<ErrorResponseBody>();
      expect(body.error.code).toBeTruthy();
    } finally {
      await close();
    }
  });
});
