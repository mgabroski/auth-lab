import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AppError } from '../../../../src/shared/http/errors';

// IMPORTANT: mock jose BEFORE importing code that depends on it.
vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(() => ({})),
  jwtVerify: vi.fn(),
}));

import { jwtVerify } from 'jose';
import { MicrosoftSsoAdapter } from '../../../../src/modules/auth/sso/microsoft/microsoft-sso.adapter';
import { buildFakeIdToken } from '../../../helpers/sso-test-fixtures';

const CLIENT_ID = 'test-microsoft-client-id';

function expectStatus(err: unknown, status: number): void {
  expect(err).toBeInstanceOf(AppError);
  expect((err as AppError).status).toBe(status);
}

describe('MicrosoftSsoAdapter.validateAndExtractIdentity', () => {
  const jwtVerifyMock = jwtVerify as unknown as ReturnType<typeof vi.fn>;

  beforeEach(() => {
    jwtVerifyMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('authorization URL includes PKCE S256 challenge and never exposes verifier', () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');

    const url = new URL(
      adapter.buildAuthorizationUrl({
        redirectUri: 'https://tenant.example/api/auth/sso/microsoft/callback',
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
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
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
      redirectUri: 'https://tenant.example/api/auth/sso/microsoft/callback',
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

  it('valid token → extracts email, sub, name (preferred_username fallback)', async () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');

    // NOTE: tid must be present in the raw JWT payload for issuer construction.
    const idToken = buildFakeIdToken({ tid: 'tenant-123' });

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        sub: 'sub-1',
        preferred_username: 'USER@Example.com',
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

  it('email claim takes precedence over preferred_username and upn', async () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({ tid: 'tenant-123' });

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        sub: 'sub-1',
        email: 'PRIMARY@Example.com',
        preferred_username: 'fallback@example.com',
        upn: 'second-fallback@example.com',
      },
    });

    const identity = await adapter.validateAndExtractIdentity({
      idToken,
      expectedNonce: 'n1',
      now: new Date(),
    });

    expect(identity.email).toBe('primary@example.com');
  });

  it('tid missing in raw payload → 401', async () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({}); // no tid

    try {
      await adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() });
      throw new Error('expected throw');
    } catch (e) {
      expectStatus(e, 401);
    }
  });

  it('jwtVerify rejects (issuer/audience/exp/sig) → 401', async () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({ tid: 'tenant-123' });

    jwtVerifyMock.mockRejectedValueOnce(new Error('bad_jwt'));

    try {
      await adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() });
      throw new Error('expected throw');
    } catch (e) {
      expectStatus(e, 401);
    }
  });

  it('nonce mismatch → 401', async () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({ tid: 'tenant-123' });

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        sub: 'sub-1',
        preferred_username: 'a@example.com',
      },
    });

    try {
      await adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n2', now: new Date() });
      throw new Error('expected throw');
    } catch (e) {
      expectStatus(e, 401);
    }
  });

  it('email resolved from upn when email/preferred_username missing', async () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({ tid: 'tenant-123' });

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        sub: 'sub-1',
        upn: 'UPN@Example.com',
      },
    });

    const identity = await adapter.validateAndExtractIdentity({
      idToken,
      expectedNonce: 'n1',
      now: new Date(),
    });

    expect(identity.email).toBe('upn@example.com');
  });

  it('no email-like claim → 401', async () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({ tid: 'tenant-123' });

    jwtVerifyMock.mockResolvedValueOnce({
      payload: {
        nonce: 'n1',
        sub: 'sub-1',
        preferred_username: 'not-an-email',
      },
    });

    try {
      await adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() });
      throw new Error('expected throw');
    } catch (e) {
      expectStatus(e, 401);
    }
  });
});
