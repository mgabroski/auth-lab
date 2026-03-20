import { describe, expect, it } from 'vitest';

import { EncryptionService } from '../../../../src/shared/security/encryption';
import { AppError } from '../../../../src/shared/http/errors';
import { buildEncryptedSsoState } from '../../../../src/modules/auth/helpers/sso-state';
import { decryptAndValidateSsoState } from '../../../../src/modules/auth/helpers/sso-state-validate';

const ENCRYPTION_KEY = 'VjJlYds7lPHtOzCrEQNNR0O7Ukst5HzX+cnszDyXvq0=';

function createEncryptionService(): EncryptionService {
  return new EncryptionService(ENCRYPTION_KEY);
}

function expectAppErrorStatus(err: unknown, status: number): void {
  expect(err).toBeInstanceOf(AppError);
  expect((err as AppError).status).toBe(status);
}

describe('decryptAndValidateSsoState', () => {
  it('accepts a safe app-relative returnTo path', () => {
    const encryptionService = createEncryptionService();
    const now = new Date('2026-03-20T10:00:00.000Z');

    const { state } = buildEncryptedSsoState({
      encryptionService,
      provider: 'google',
      tenantKey: 'goodwill-ca',
      requestId: 'req-1',
      redirectUri: 'http://goodwill-ca.lvh.me:3000/api/auth/sso/google/callback',
      returnTo: '/admin',
      now,
    });

    const payload = decryptAndValidateSsoState({
      encryptionService,
      encryptedState: state,
      provider: 'google',
      tenantKey: 'goodwill-ca',
      now: new Date(now.getTime() + 1_000),
    });

    expect(payload.returnTo).toBe('/admin');
  });

  it('drops an absolute returnTo URL after decrypting state', () => {
    const encryptionService = createEncryptionService();
    const now = new Date('2026-03-20T10:00:00.000Z');
    const state = encryptionService.encrypt(
      JSON.stringify({
        provider: 'google',
        tenantKey: 'goodwill-ca',
        nonce: 'nonce-1',
        issuedAt: now.getTime(),
        expiresAt: now.getTime() + 60_000,
        requestId: 'req-1',
        redirectUri: 'http://goodwill-ca.lvh.me:3000/api/auth/sso/google/callback',
        returnTo: 'https://evil.example',
      }),
    );

    const payload = decryptAndValidateSsoState({
      encryptionService,
      encryptedState: state,
      provider: 'google',
      tenantKey: 'goodwill-ca',
      now: new Date(now.getTime() + 1_000),
    });

    expect(payload.returnTo).toBeUndefined();
  });

  it('drops a scheme-relative returnTo path after decrypting state', () => {
    const encryptionService = createEncryptionService();
    const now = new Date('2026-03-20T10:00:00.000Z');
    const state = encryptionService.encrypt(
      JSON.stringify({
        provider: 'google',
        tenantKey: 'goodwill-ca',
        nonce: 'nonce-1',
        issuedAt: now.getTime(),
        expiresAt: now.getTime() + 60_000,
        requestId: 'req-1',
        redirectUri: 'http://goodwill-ca.lvh.me:3000/api/auth/sso/google/callback',
        returnTo: '//evil.example',
      }),
    );

    const payload = decryptAndValidateSsoState({
      encryptionService,
      encryptedState: state,
      provider: 'google',
      tenantKey: 'goodwill-ca',
      now: new Date(now.getTime() + 1_000),
    });

    expect(payload.returnTo).toBeUndefined();
  });

  it('drops a backslash-based returnTo path after decrypting state', () => {
    const encryptionService = createEncryptionService();
    const now = new Date('2026-03-20T10:00:00.000Z');
    const state = encryptionService.encrypt(
      JSON.stringify({
        provider: 'google',
        tenantKey: 'goodwill-ca',
        nonce: 'nonce-1',
        issuedAt: now.getTime(),
        expiresAt: now.getTime() + 60_000,
        requestId: 'req-1',
        redirectUri: 'http://goodwill-ca.lvh.me:3000/api/auth/sso/google/callback',
        returnTo: '/\\evil',
      }),
    );

    const payload = decryptAndValidateSsoState({
      encryptionService,
      encryptedState: state,
      provider: 'google',
      tenantKey: 'goodwill-ca',
      now: new Date(now.getTime() + 1_000),
    });

    expect(payload.returnTo).toBeUndefined();
  });

  it('rejects malformed encrypted state with the standard SSO state error', () => {
    const encryptionService = createEncryptionService();

    try {
      decryptAndValidateSsoState({
        encryptionService,
        encryptedState: 'not-valid-base64-ciphertext',
        provider: 'google',
        tenantKey: 'goodwill-ca',
        now: new Date('2026-03-20T10:00:00.000Z'),
      });
      throw new Error('expected throw');
    } catch (err) {
      expectAppErrorStatus(err, 400);
      expect((err as AppError).message).toBe('Invalid or expired SSO request. Please try again.');
    }
  });
});
