import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { buildTestApp } from '../helpers/build-test-app';

const HealthResponseSchema = z.object({
  ok: z.boolean(),
  env: z.string(),
  service: z.string().optional(), // in case you include it
  requestId: z.string(),
  tenantKey: z.string().nullable(),
});

type HealthResponse = z.infer<typeof HealthResponseSchema>;

describe('GET /health', () => {
  it('returns ok payload and resolves tenantKey from host', async () => {
    const { app, close } = await buildTestApp();

    try {
      const res = await app.inject({
        method: 'GET',
        url: '/health',
        headers: { host: 'goodwill-ca.localhost:3000' },
      });

      expect(res.statusCode).toBe(200);

      const parsed: HealthResponse = HealthResponseSchema.parse(res.json());

      expect(parsed.ok).toBe(true);
      expect(parsed.env).toBe('test');
      expect(typeof parsed.requestId).toBe('string');
      expect(parsed.tenantKey).toBe('goodwill-ca');
    } finally {
      await close();
    }
  });
});
