/**
 * backend/test/e2e/request-context.spec.ts
 *
 * WHY:
 * - Locks the topology-sensitive request context behavior used by Stage 2 + Stage 3.
 * - Proves host / forwarded-host resolution remains correct.
 * - Proves request ID propagation is stable and operator-visible.
 *
 * STAGE 3:
 * - Preserves sanitized inbound x-request-id when present.
 * - Falls back to x-correlation-id when x-request-id is absent.
 * - Rejects malformed inbound IDs and generates a fresh request ID instead.
 * - Confirms the response echoes x-request-id so operators can correlate failures.
 */

import type { OutgoingHttpHeaders } from 'node:http';
import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';

type HealthResponse = {
  ok: boolean;
  env: string;
  service?: string;
  requestId: string;
  tenantKey: string | null;
};

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function readHeader(res: { headers: OutgoingHttpHeaders }, name: string): string | undefined {
  const value = res.headers[name];

  if (Array.isArray(value)) {
    const first = value[0];
    return typeof first === 'number' ? String(first) : first;
  }

  if (typeof value === 'number') {
    return String(value);
  }

  return value;
}

describe('request context', () => {
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

      expect(readHeader(res, 'x-request-id')).toBe(body.requestId);
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
      expect(readHeader(res, 'x-request-id')).toBe(body.requestId);
    } finally {
      await close();
    }
  });

  it('preserves a sanitized inbound x-request-id and echoes it on the response', async () => {
    const { app, close } = await buildTestApp();
    const inboundRequestId = 'stage3-request-id-001';

    try {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
        headers: {
          host: 'goodwill-ca.localhost:3000',
          'x-request-id': inboundRequestId,
        },
      });

      expect(res.statusCode).toBe(200);

      const body = readJson<HealthResponse>(res);
      expect(body.requestId).toBe(inboundRequestId);
      expect(readHeader(res, 'x-request-id')).toBe(inboundRequestId);
    } finally {
      await close();
    }
  });

  it('falls back to x-correlation-id when x-request-id is absent', async () => {
    const { app, close } = await buildTestApp();
    const correlationId = 'stage3-correlation-id-001';

    try {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
        headers: {
          host: 'goodwill-ca.localhost:3000',
          'x-correlation-id': correlationId,
        },
      });

      expect(res.statusCode).toBe(200);

      const body = readJson<HealthResponse>(res);
      expect(body.requestId).toBe(correlationId);
      expect(readHeader(res, 'x-request-id')).toBe(correlationId);
    } finally {
      await close();
    }
  });

  it('rejects a malformed inbound x-request-id and generates a fresh request id', async () => {
    const { app, close } = await buildTestApp();
    const malformedRequestId = 'bad request id with spaces';

    try {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
        headers: {
          host: 'goodwill-ca.localhost:3000',
          'x-request-id': malformedRequestId,
        },
      });

      expect(res.statusCode).toBe(200);

      const body = readJson<HealthResponse>(res);
      const responseRequestId = readHeader(res, 'x-request-id');

      expect(body.requestId).toEqual(expect.any(String));
      expect(body.requestId).not.toBe(malformedRequestId);
      expect(responseRequestId).toBe(body.requestId);
      expect(responseRequestId).not.toBe(malformedRequestId);
    } finally {
      await close();
    }
  });
});
