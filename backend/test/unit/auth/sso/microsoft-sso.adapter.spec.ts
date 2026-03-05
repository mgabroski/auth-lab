import { describe, it, expect, vi, beforeEach } from 'vitest';
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
