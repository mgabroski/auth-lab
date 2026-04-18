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

describe('cp accounts create', () => {
  it('rejects reserved account keys before draft creation', async () => {
    const { app, close, reset } = await buildTestApp();
    const reservedKeys = ['cp', 'api', 'admin', 'auth', 'www', 'app'];

    try {
      await reset();

      for (const accountKey of reservedKeys) {
        const res = await app.inject({
          method: 'POST',
          url: '/cp/accounts',
          payload: {
            accountName: `Reserved ${accountKey.toUpperCase()} Tenant`,
            accountKey,
          },
        });

        expect(res.statusCode).toBe(400);
        expect(readJson<ErrorResponseBody>(res)).toEqual({
          error: {
            code: 'VALIDATION_ERROR',
            message: `Account key is reserved and cannot be used: ${accountKey}`,
          },
        });
      }

      const listRes = await app.inject({
        method: 'GET',
        url: '/cp/accounts',
      });

      expect(listRes.statusCode).toBe(200);
      expect(readJson<{ accounts: Array<{ accountKey: string }> }>(listRes)).toEqual({
        accounts: [],
      });
    } finally {
      await close();
    }
  });
});
