import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';

type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
  };
};

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

describe('cp accounts host boundary', () => {
  it('rejects tenant-host access to /cp/* with a generic 404', async () => {
    const { app, close, reset } = await buildTestApp();

    try {
      await reset();

      const res = await app.inject({
        method: 'GET',
        url: '/cp/accounts',
        headers: {
          host: 'goodwill-ca.lvh.me:3000',
          'x-forwarded-host': 'goodwill-ca.lvh.me:3000',
          'x-forwarded-proto': 'http',
        },
      });

      expect(res.statusCode).toBe(404);
      expect(readJson<ErrorResponseBody>(res)).toEqual({
        error: {
          code: 'NOT_FOUND',
          message: 'Not found',
        },
      });
    } finally {
      await close();
    }
  });

  it('allows the dedicated CP host to reach /cp/*', async () => {
    const { app, close, reset } = await buildTestApp();

    try {
      await reset();

      const res = await app.inject({
        method: 'GET',
        url: '/cp/accounts',
        headers: {
          host: 'cp.lvh.me:3000',
          'x-forwarded-host': 'cp.lvh.me:3000',
          'x-forwarded-proto': 'http',
        },
      });

      expect(res.statusCode).toBe(200);
      expect(readJson<{ accounts: unknown[] }>(res)).toEqual({ accounts: [] });
    } finally {
      await close();
    }
  });
});
