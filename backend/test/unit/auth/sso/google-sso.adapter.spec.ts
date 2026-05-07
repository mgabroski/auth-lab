import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
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

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('authorization URL includes PKCE S256 challenge and never exposes verifier', () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');

    const url = new URL(
      adapter.buildAuthorizationUrl({
        redirectUri: 'https://tenant.example/api/auth/sso/google/callback',
        state: 'encrypted-state',
        nonce: 'nonce-1',
        pkceCodeChallenge: 'challenge-1',
      }),
    );

    expect(url.searchParams.get('code_challenge')).toBe('challenge-1');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.has('code_verifier')).toBe(false);
  });

  it('token exchange sends the PKCE verifier', async () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const fetchMock = vi.fn((_url: string | URL | Request, _init?: RequestInit) =>
      Promise.resolve(
        new Response(JSON.stringify({ id_token: 'id-token' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = await adapter.exchangeAuthorizationCode({
      code: 'provider-code',
      redirectUri: 'https://tenant.example/api/auth/sso/google/callback',
      pkceCodeVerifier: 'verifier-1',
    });

    expect(result).toEqual({ idToken: 'id-token' });
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init).toBeDefined();
    const body = init?.body;
    expect(body).toBeInstanceOf(URLSearchParams);
    if (!(body instanceof URLSearchParams)) throw new Error('expected URLSearchParams body');
    expect(body.get('code_verifier')).toBe('verifier-1');
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
