import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';

async function createTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  allowedSso?: Array<'google' | 'microsoft'>;
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: 'Test Tenant',
      is_active: true,
      public_signup_enabled: false,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
      allowed_sso: opts.allowedSso ?? ['google', 'microsoft'],
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();
}

describe('GET /auth/sso/:provider', () => {
  it('returns 302 and includes state + nonce query parameters when provider is allowed', async () => {
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
      expect(res.headers['set-cookie']).toBeTruthy();
    } finally {
      await close();
    }
  });

  it('returns 403 and does not start OAuth redirect when provider is disabled for the tenant', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createTenant({ db, tenantKey, allowedSso: ['microsoft'] });

      const res = await app.inject({
        method: 'GET',
        url: '/auth/sso/google',
        headers: { host },
      });

      expect(res.statusCode).toBe(403);
      expect(res.headers.location).toBeUndefined();
      expect(res.headers['set-cookie']).toBeUndefined();
      expect(res.json()).toEqual({
        error: {
          code: 'FORBIDDEN',
          message: 'This sign-in method is not enabled for this workspace.',
        },
      });
    } finally {
      await close();
    }
  });
});

describe('GET /auth/sso/:provider/callback', () => {
  it('returns 400 when required query params are missing (PR2)', async () => {
    const { app, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const res = await app.inject({
        method: 'GET',
        url: '/auth/sso/google/callback',
        headers: { host },
      });

      expect(res.statusCode).toBe(400);
    } finally {
      await close();
    }
  });
});
