// backend/test/e2e/auth-sso-start.spec.ts
import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';

async function createTenant(opts: { db: DbExecutor; tenantKey: string }) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: 'Test Tenant',
      is_active: true,
      public_signup_enabled: false,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
      allowed_sso: ['google', 'microsoft'],
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();
}

describe('GET /auth/sso/:provider', () => {
  it('returns 302 and includes state + nonce query parameters', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createTenant({ db, tenantKey });

      const res = await app.inject({
        method: 'GET',
        url: '/auth/sso/google',
        headers: { host },
      });

      expect(res.statusCode).toBe(302);

      const location = res.headers.location;
      expect(typeof location).toBe('string');

      const loc = String(location);
      expect(loc).toContain('state=');
      expect(loc).toContain('nonce=');
    } finally {
      await close();
    }
  });
});

describe('GET /auth/sso/:provider/callback', () => {
  it('returns 501 Not Implemented (PR1 stub)', async () => {
    const { app, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const res = await app.inject({
        method: 'GET',
        url: '/auth/sso/google/callback',
        headers: { host },
      });

      expect(res.statusCode).toBe(501);
    } finally {
      await close();
    }
  });
});
