/**
 * backend/test/e2e/metrics.spec.ts
 *
 * WHY:
 * - Stage 3 requires real operability proof, not just implementation.
 * - Verifies the backend exports Prometheus-text metrics.
 * - Verifies known failures increment the expected counters.
 *
 * CURRENT PROOF:
 * - /metrics is reachable and returns Prometheus text.
 * - /health requests appear in http request metrics.
 * - failed login increments auth_login_failures_total.
 * - missing-tenant login failure increments tenant_resolution_failures_total.
 *
 * RULES:
 * - Low-cardinality assertions only.
 * - Do not assert on volatile request IDs or timestamps.
 * - Keep failure scenarios deterministic and cheap.
 */

import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { describe, expect, it } from 'vitest';

import type { DbExecutor } from '../../src/shared/db/db';
import { buildTestApp } from '../helpers/build-test-app';

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

function readText(res: { body: string }): string {
  return res.body;
}

function expectMetricLine(metricsText: string, expectedLine: string): void {
  expect(metricsText).toContain(expectedLine);
}

async function createTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  isActive?: boolean;
  publicSignupEnabled?: boolean;
  adminInviteRequired?: boolean;
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
      admin_invite_required: opts.adminInviteRequired ?? false,
      member_mfa_required: opts.memberMfaRequired ?? false,
      allowed_email_domains: opts.allowedEmailDomains?.length
        ? sql`${JSON.stringify(opts.allowedEmailDomains)}::jsonb`
        : sql`'[]'::jsonb`,
      allowed_sso: opts.allowedSso ?? [],
    })
    .returning(['id', 'key', 'name'])
    .executeTakeFirstOrThrow();
}

describe('GET /metrics', () => {
  it('returns Prometheus-text metrics and includes http request metrics for /health', async () => {
    const { app, close } = await buildTestApp();

    try {
      const healthRes = await app.inject({
        method: 'GET',
        url: '/health',
        headers: {
          host: 'goodwill-ca.localhost:3000',
          'x-request-id': 'metrics-health-001',
        },
      });

      expect(healthRes.statusCode).toBe(200);

      const metricsRes = await app.inject({
        method: 'GET',
        url: '/metrics',
        headers: {
          host: 'goodwill-ca.localhost:3000',
        },
      });

      expect(metricsRes.statusCode).toBe(200);
      expect(metricsRes.headers['content-type']).toContain('text/plain');

      const metricsText = readText(metricsRes);

      expect(metricsText).toContain('# HELP http_requests_total');
      expect(metricsText).toContain('# TYPE http_requests_total counter');
      expect(metricsText).toContain('# HELP http_request_duration_ms');
      expect(metricsText).toContain('# TYPE http_request_duration_ms histogram');

      expectMetricLine(
        metricsText,
        'http_requests_total{method="GET",route="/health",status="200",status_class="2xx"} 1',
      );
    } finally {
      await close();
    }
  });

  it('increments auth_login_failures_total for an invalid-credentials login attempt', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `login-metrics-${randomUUID().slice(0, 8)}`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey,
        isActive: true,
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: {
          host: hostForTenant(tenantKey),
          'content-type': 'application/json',
          'x-request-id': 'metrics-login-failure-001',
        },
        payload: {
          email: 'missing-user@example.com',
          password: 'WrongPassword123!',
        },
      });

      expect(loginRes.statusCode).toBe(401);

      const metricsRes = await app.inject({
        method: 'GET',
        url: '/metrics',
        headers: {
          host: hostForTenant(tenantKey),
        },
      });

      expect(metricsRes.statusCode).toBe(200);

      const metricsText = readText(metricsRes);

      expect(metricsText).toContain('# HELP auth_login_failures_total');
      expectMetricLine(
        metricsText,
        'auth_login_failures_total{reason="unauthorized",code="UNAUTHORIZED",status="401"} 1',
      );
    } finally {
      await close();
    }
  });

  it('increments tenant_resolution_failures_total when login is attempted without tenant context', async () => {
    const { app, close } = await buildTestApp();

    try {
      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: {
          host: 'localhost:3001',
          'content-type': 'application/json',
          'x-request-id': 'metrics-tenant-failure-001',
        },
        payload: {
          email: 'nobody@example.com',
          password: 'WrongPassword123!',
        },
      });

      expect(loginRes.statusCode).toBe(404);

      const metricsRes = await app.inject({
        method: 'GET',
        url: '/metrics',
        headers: {
          host: 'localhost:3001',
        },
      });

      expect(metricsRes.statusCode).toBe(200);

      const metricsText = readText(metricsRes);

      expect(metricsText).toContain('# HELP tenant_resolution_failures_total');
      expectMetricLine(
        metricsText,
        'tenant_resolution_failures_total{route="/auth/login",reason="missing_key",status="404"} 1',
      );
    } finally {
      await close();
    }
  });
});
