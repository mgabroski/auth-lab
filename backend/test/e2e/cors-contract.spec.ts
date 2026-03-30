/**
 * backend/test/e2e/cors-contract.spec.ts
 *
 * WHY:
 * - Locks the Stage 2 same-origin contract from the backend side.
 * - Prevents accidental CORS enablement on auth endpoints.
 * - Browser traffic must stay same-origin through the proxy or host-run shim.
 *
 * RULES:
 * - Do not assert on a specific non-CORS status for preflight; the load-bearing
 *   rule is that CORS response headers are absent.
 * - Use a real tenant host for endpoint requests so the request shape matches
 *   the intended topology.
 */

import { randomUUID } from 'node:crypto';
import type { OutgoingHttpHeaders } from 'node:http';

import { sql } from 'kysely';
import { describe, expect, it } from 'vitest';

import type { DbExecutor } from '../../src/shared/db/db';
import { buildTestApp } from '../helpers/build-test-app';

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

function expectNoCorsHeaders(headers: OutgoingHttpHeaders, context: string) {
  expect(headers['access-control-allow-origin'], `${context}: ACAO must be absent`).toBeUndefined();
  expect(
    headers['access-control-allow-credentials'],
    `${context}: ACAC must be absent`,
  ).toBeUndefined();
  expect(
    headers['access-control-allow-methods'],
    `${context}: ACAM must be absent`,
  ).toBeUndefined();
  expect(
    headers['access-control-allow-headers'],
    `${context}: ACAH must be absent`,
  ).toBeUndefined();
}

async function createTenant(opts: { db: DbExecutor; tenantKey: string }) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: false,
      admin_invite_required: false,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
      allowed_sso: [],
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();
}

describe('backend no-CORS auth contract', () => {
  it('does not emit CORS headers on GET /auth/config even when Origin is present', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `cors-config-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: {
          host: hostForTenant(tenantKey),
          origin: 'https://evil.example.com',
        },
      });

      expect(res.statusCode).toBe(200);
      expectNoCorsHeaders(res.headers, 'GET /auth/config');
    } finally {
      await close();
    }
  });

  it('does not emit CORS headers for browser-style preflight to /auth/login', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `cors-preflight-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey,
      });

      const res = await app.inject({
        method: 'OPTIONS',
        url: '/auth/login',
        headers: {
          host: hostForTenant(tenantKey),
          origin: 'https://evil.example.com',
          'access-control-request-method': 'POST',
          'access-control-request-headers': 'content-type',
        },
      });

      expectNoCorsHeaders(res.headers, 'OPTIONS /auth/login');
    } finally {
      await close();
    }
  });

  it('does not emit CORS headers on POST /auth/login when Origin is present', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `cors-login-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: {
          host: hostForTenant(tenantKey),
          origin: 'https://evil.example.com',
          'content-type': 'application/json',
        },
        payload: {
          email: 'nobody@example.com',
          password: 'WrongPassword123!',
        },
      });

      expect([400, 401]).toContain(res.statusCode);
      expectNoCorsHeaders(res.headers, 'POST /auth/login');
    } finally {
      await close();
    }
  });
});
