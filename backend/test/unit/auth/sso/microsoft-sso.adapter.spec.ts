import { describe, it, expect } from 'vitest';
import { MicrosoftSsoAdapter } from '../../../../src/modules/auth/sso/microsoft/microsoft-sso.adapter';
import { buildFakeIdToken } from '../../../helpers/sso-test-fixtures';
import { AppError } from '../../../../src/shared/http/errors';

const CLIENT_ID = 'test-microsoft-client-id';

describe('MicrosoftSsoAdapter.validateAndExtractIdentity', () => {
  it('valid token → extracts email, sub, name', () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      tid: 'tenant-123',
      iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      sub: 'sub-1',
      preferred_username: 'USER@Example.com',
      name: 'User Name',
    });

    const identity = adapter.validateAndExtractIdentity({
      idToken,
      expectedNonce: 'n1',
      now: new Date(),
    });

    expect(identity).toEqual({ email: 'user@example.com', sub: 'sub-1', name: 'User Name' });
  });

  it('tid missing → 401', () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      sub: 'sub-1',
      preferred_username: 'a@example.com',
    });

    try {
      adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() });
      throw new Error('expected throw');
    } catch (e) {
      expect((e as AppError).status).toBe(401);
    }
  });

  it('issuer mismatch (wrong tid) → 401', () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      tid: 'tenant-123',
      iss: 'https://login.microsoftonline.com/tenant-999/v2.0',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      sub: 'sub-1',
      preferred_username: 'a@example.com',
    });

    try {
      adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() });
      throw new Error('expected throw');
    } catch (e) {
      expect((e as AppError).status).toBe(401);
    }
  });

  it('audience mismatch → 401', () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      tid: 'tenant-123',
      iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
      aud: 'other-client',
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      sub: 'sub-1',
      preferred_username: 'a@example.com',
    });

    try {
      adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() });
      throw new Error('expected throw');
    } catch (e) {
      expect((e as AppError).status).toBe(401);
    }
  });

  it('expired exp → 401', () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      tid: 'tenant-123',
      iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) - 1,
      nonce: 'n1',
      sub: 'sub-1',
      preferred_username: 'a@example.com',
    });

    try {
      adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() });
      throw new Error('expected throw');
    } catch (e) {
      expect((e as AppError).status).toBe(401);
    }
  });

  it('nonce mismatch → 401', () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      tid: 'tenant-123',
      iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      sub: 'sub-1',
      preferred_username: 'a@example.com',
    });

    try {
      adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n2', now: new Date() });
      throw new Error('expected throw');
    } catch (e) {
      expect((e as AppError).status).toBe(401);
    }
  });

  it('email via preferred_username fallback → success', () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      tid: 'tenant-123',
      iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      sub: 'sub-1',
      preferred_username: 'x@example.com',
    });

    const identity = adapter.validateAndExtractIdentity({
      idToken,
      expectedNonce: 'n1',
      now: new Date(),
    });
    expect(identity.email).toBe('x@example.com');
  });

  it('email via upn fallback → success', () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      tid: 'tenant-123',
      iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      sub: 'sub-1',
      upn: 'x@example.com',
    });

    const identity = adapter.validateAndExtractIdentity({
      idToken,
      expectedNonce: 'n1',
      now: new Date(),
    });
    expect(identity.email).toBe('x@example.com');
  });

  it('all email fields missing → 401', () => {
    const adapter = new MicrosoftSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      tid: 'tenant-123',
      iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      sub: 'sub-1',
    });

    try {
      adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() });
      throw new Error('expected throw');
    } catch (e) {
      expect((e as AppError).status).toBe(401);
    }
  });
});
