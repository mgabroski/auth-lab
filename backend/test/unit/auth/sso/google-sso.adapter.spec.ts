import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AppError } from '../../../../src/shared/http/errors';

// IMPORTANT: mock jose BEFORE importing code that depends on it.
vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(() => ({})),
  jwtVerify: vi.fn(),
}));

import { jwtVerify } from 'jose';
import { GoogleSsoAdapter } from '../../../../src/modules/auth/sso/google/google-sso.adapter';
import { buildFakeIdToken } from '../../../helpers/sso-test-fixtures';

const CLIENT_ID = 'test-google-client-id';

function expectAppErrorStatus(err: unknown, status: number): void {
  expect(err).toBeInstanceOf(AppError);
  expect((err as AppError).status).toBe(status);
}

describe('GoogleSsoAdapter.validateAndExtractIdentity', () => {
  const jwtVerifyMock = jwtVerify as unknown as ReturnType<typeof vi.fn>;

  beforeEach(() => {
    jwtVerifyMock.mockReset();
  });

  it('valid token → extracts email, sub, name', async () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({}); // body ignored by mocked jwtVerify

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        email: 'USER@Example.com',
        email_verified: true,
        sub: 'sub-1',
        name: 'User Name',
      },
    });

    const identity = await adapter.validateAndExtractIdentity({
      idToken,
      expectedNonce: 'n1',
      now: new Date(),
    });

    expect(identity).toEqual({ email: 'user@example.com', sub: 'sub-1', name: 'User Name' });
  });

  it('jwtVerify rejects (issuer/audience/exp/sig) → 401', async () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    jwtVerifyMock.mockRejectedValueOnce(new Error('bad_jwt'));

    try {
      await adapter.validateAndExtractIdentity({
        idToken: buildFakeIdToken({}),
        expectedNonce: 'n1',
        now: new Date(),
      });
      throw new Error('expected throw');
    } catch (e) {
      expectAppErrorStatus(e, 401);
    }
  });

  it('nonce mismatch → 401', async () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        email: 'a@example.com',
        email_verified: true,
        sub: 'sub-1',
      },
    });

    try {
      await adapter.validateAndExtractIdentity({
        idToken: buildFakeIdToken({}),
        expectedNonce: 'n2',
        now: new Date(),
      });
      throw new Error('expected throw');
    } catch (e) {
      expectAppErrorStatus(e, 401);
    }
  });

  it('email_verified === false → 403', async () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        email: 'a@example.com',
        email_verified: false,
        sub: 'sub-1',
      },
    });

    try {
      await adapter.validateAndExtractIdentity({
        idToken: buildFakeIdToken({}),
        expectedNonce: 'n1',
        now: new Date(),
      });
      throw new Error('expected throw');
    } catch (e) {
      expectAppErrorStatus(e, 403);
    }
  });

  it('email_verified missing → 403', async () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        email: 'a@example.com',
        sub: 'sub-1',
      },
    });

    try {
      await adapter.validateAndExtractIdentity({
        idToken: buildFakeIdToken({}),
        expectedNonce: 'n1',
        now: new Date(),
      });
      throw new Error('expected throw');
    } catch (e) {
      expectAppErrorStatus(e, 403);
    }
  });

  it('email claim missing → 401', async () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        email_verified: true,
        sub: 'sub-1',
      },
    });

    try {
      await adapter.validateAndExtractIdentity({
        idToken: buildFakeIdToken({}),
        expectedNonce: 'n1',
        now: new Date(),
      });
      throw new Error('expected throw');
    } catch (e) {
      expectAppErrorStatus(e, 401);
    }
  });

  it('sub claim missing → 401', async () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        email: 'a@example.com',
        email_verified: true,
      },
    });

    try {
      await adapter.validateAndExtractIdentity({
        idToken: buildFakeIdToken({}),
        expectedNonce: 'n1',
        now: new Date(),
      });
      throw new Error('expected throw');
    } catch (e) {
      expectAppErrorStatus(e, 401);
    }
  });
});
