import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import { getLatestOutboxPayloadForUser } from '../helpers/outbox-test-helpers';
import type { DbExecutor } from '../../src/shared/db/db';
/**
 * E2E tests for POST /auth/signup (Brick 11).
 */

type SignupResponseBody = {
  status: 'EMAIL_VERIFICATION_REQUIRED' | 'AUTHENTICATED';
  nextAction: string;
};

async function createTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  publicSignupEnabled?: boolean;
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: opts.publicSignupEnabled ?? true,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

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

describe('POST /auth/signup', () => {
  it('new user → 201, EMAIL_VERIFICATION_REQUIRED, session cookie, verification email enqueued', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `tenant-${randomUUID()}`;
    const email = `user-${randomUUID()}@example.com`;
    const password = 'Password123!';

    try {
      // Tenant must exist so tenant resolution from Host works.
      await createTenant({ db, tenantKey, publicSignupEnabled: true });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/signup',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password, name: 'Test User' },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json<SignupResponseBody>();
      expect(body.status).toBe('EMAIL_VERIFICATION_REQUIRED');

      const cookie = extractCookie(res);
      expect(cookie).toContain('HttpOnly');

      const users = await db
        .selectFrom('users')
        .selectAll()
        .where('email', '=', email.toLowerCase())
        .execute();
      expect(users).toHaveLength(1);
      expect(users[0].email_verified).toBe(false);

      const tokens = await db
        .selectFrom('email_verification_tokens')
        .selectAll()
        .where('user_id', '=', users[0].id)
        .where('used_at', 'is', null)
        .execute();
      expect(tokens).toHaveLength(1);

      // Outbox row exists (type must match OutboxMessageType union)
      const outboxPayload = await getLatestOutboxPayloadForUser({
        db,
        outboxEncryption: deps.outboxEncryption,
        userId: users[0].id,
        type: 'email.verify',
      });
      expect(outboxPayload).toBeTruthy();
    } finally {
      await close();
    }
  });

  it('public signup disabled → 403', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `tenant-${randomUUID()}`;
    const email = `user-${randomUUID()}@example.com`;

    try {
      await createTenant({ db, tenantKey, publicSignupEnabled: false });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/signup',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password: 'Password123!', name: 'Test User' },
      });

      expect(res.statusCode).toBe(403);
    } finally {
      await close();
    }
  });
});
