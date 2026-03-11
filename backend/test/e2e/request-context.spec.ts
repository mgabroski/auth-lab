/**
 * backend/test/e2e/request-context.spec.ts
 *
 * WHY:
 * - Locks the topology-sensitive host/forwarded-host resolution rules.
 * - Protects the SSR/direct-backend contract used by the frontend foundation.
 * - Prevents silent regressions in tenant resolution when Host and
 *   X-Forwarded-Host differ.
 */

import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';

type HealthResponse = {
  ok: boolean;
  requestId: string;
  tenantKey: string | null;
};

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

describe('request context host resolution', () => {
  it('uses x-forwarded-host when direct backend host lacks tenant context', async () => {
    const { app, close } = await buildTestApp();

    try {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
        headers: {
          host: 'localhost:3001',
          'x-forwarded-host': 'goodwill-ca.localhost:3000',
          'x-forwarded-proto': 'https',
        },
      });

      expect(res.statusCode).toBe(200);

      const body = readJson<HealthResponse>(res);
      expect(body.ok).toBe(true);
      expect(body.tenantKey).toBe('goodwill-ca');
      expect(body.requestId).toEqual(expect.any(String));
    } finally {
      await close();
    }
  });

  it('prefers the tenant-bearing host when host already contains tenant context', async () => {
    const { app, close } = await buildTestApp();

    try {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
        headers: {
          host: 'tenant-from-host.localhost:3000',
          'x-forwarded-host': 'tenant-from-forwarded.localhost:3000',
          'x-forwarded-proto': 'https',
        },
      });

      expect(res.statusCode).toBe(200);

      const body = readJson<HealthResponse>(res);
      expect(body.ok).toBe(true);
      expect(body.tenantKey).toBe('tenant-from-host');
    } finally {
      await close();
    }
  });
});
