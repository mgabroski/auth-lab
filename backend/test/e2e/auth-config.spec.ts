/**
 * backend/test/e2e/auth-config.spec.ts
 *
 * WHY:
 * - Verifies GET /auth/config as the public frontend bootstrap endpoint.
 * - Locks anti-enumeration parity for unknown vs inactive tenants.
 * - Verifies only public-safe tenant auth config is exposed.
 *
 * RULES:
 * - Build a fresh app per test.
 * - Seed tenants directly with deps.db.
 * - No session cookie is required for this endpoint.
 */

import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { describe, expect, it } from 'vitest';

import type { ConfigResponse } from '../../src/modules/auth/auth.types';
import type { DbExecutor } from '../../src/shared/db/db';
import { buildTestApp } from '../helpers/build-test-app';

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

async function createTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  isActive?: boolean;
  publicSignupEnabled?: boolean;
  memberMfaRequired?: boolean;
  allowedSso?: Array<'google' | 'microsoft'>;
  allowedEmailDomains?: string[];
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: opts.isActive ?? true,
      public_signup_enabled: opts.publicSignupEnabled ?? false,
      member_mfa_required: opts.memberMfaRequired ?? false,
      allowed_email_domains: opts.allowedEmailDomains?.length
        ? sql`${JSON.stringify(opts.allowedEmailDomains)}::jsonb`
        : sql`'[]'::jsonb`,
      allowed_sso: opts.allowedSso ?? [],
    })
    .returning(['id', 'key', 'name'])
    .executeTakeFirstOrThrow();
}

describe('GET /auth/config', () => {
  it('returns unavailable shape for an unknown tenant', async () => {
    const { app, close } = await buildTestApp();
    const host = hostForTenant(`unknown-${randomUUID().slice(0, 8)}`);

    try {
      const res = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: { host },
      });

      expect(res.statusCode).toBe(200);
      expect(readJson<ConfigResponse>(res)).toEqual({
        tenant: {
          name: '',
          isActive: false,
          publicSignupEnabled: false,
          allowedSso: [],
        },
      });
    } finally {
      await close();
    }
  });

  it('returns the identical unavailable shape for an inactive tenant', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `inactive-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey,
        isActive: false,
        publicSignupEnabled: true,
        allowedSso: ['google', 'microsoft'],
      });

      const unknownRes = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: { host: hostForTenant(`unknown-${randomUUID().slice(0, 8)}`) },
      });

      const inactiveRes = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: { host: hostForTenant(tenantKey) },
      });

      expect(inactiveRes.statusCode).toBe(200);
      expect(readJson<ConfigResponse>(inactiveRes)).toEqual(readJson<ConfigResponse>(unknownRes));
    } finally {
      await close();
    }
  });

  it('returns google when Google SSO is the only allowed provider', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `google-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });

      const res = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: { host: hostForTenant(tenantKey) },
      });

      expect(res.statusCode).toBe(200);
      expect(readJson<ConfigResponse>(res).tenant.allowedSso).toEqual(['google']);
    } finally {
      await close();
    }
  });

  it('returns microsoft when Microsoft SSO is the only allowed provider', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `microsoft-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });

      const res = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: { host: hostForTenant(tenantKey) },
      });

      expect(res.statusCode).toBe(200);
      expect(readJson<ConfigResponse>(res).tenant.allowedSso).toEqual(['microsoft']);
    } finally {
      await close();
    }
  });

  it('returns allowedSso in stable order when both providers are enabled', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `both-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey,
        allowedSso: ['microsoft', 'google'],
      });

      const res = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: { host: hostForTenant(tenantKey) },
      });

      expect(res.statusCode).toBe(200);
      expect(readJson<ConfigResponse>(res).tenant.allowedSso).toEqual(['google', 'microsoft']);
    } finally {
      await close();
    }
  });

  it('returns publicSignupEnabled false when signup is disabled', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `signup-off-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({ db: deps.db, tenantKey, publicSignupEnabled: false });

      const res = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: { host: hostForTenant(tenantKey) },
      });

      expect(res.statusCode).toBe(200);
      expect(readJson<ConfigResponse>(res).tenant.publicSignupEnabled).toBe(false);
    } finally {
      await close();
    }
  });

  it('never returns allowedEmailDomains', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `domains-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey,
        allowedEmailDomains: ['acme.com'],
      });

      const res = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: { host: hostForTenant(tenantKey) },
      });

      expect(res.statusCode).toBe(200);

      const body = readJson<ConfigResponse>(res);
      expect(body.tenant).not.toHaveProperty('allowedEmailDomains');
    } finally {
      await close();
    }
  });

  it('does not require a session cookie', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `public-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });

      const res = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: { host: hostForTenant(tenantKey) },
      });

      expect(res.statusCode).toBe(200);
    } finally {
      await close();
    }
  });
});
