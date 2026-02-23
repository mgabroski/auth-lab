import { describe, it, expect } from 'vitest';
import { AppError } from '../../../../src/shared/http/errors';
import { GoogleSsoAdapter as GoogleSsoAdapterAny } from '../../../../src/modules/auth/sso/google/google-sso.adapter';
import { buildFakeIdToken as buildFakeIdTokenAny } from '../../../helpers/sso-test-fixtures';

type ValidateInput = {
  idToken: string;
  expectedNonce: string;
  now: Date;
};

type Identity = {
  email: string;
  sub: string;
  name?: string;
};

type GoogleSsoAdapterCtor = new (
  clientId: string,
  clientSecret: string,
) => {
  validateAndExtractIdentity(input: ValidateInput): Identity;
};

const GoogleSsoAdapter = GoogleSsoAdapterAny as unknown as GoogleSsoAdapterCtor;
const buildFakeIdToken = buildFakeIdTokenAny as unknown as (
  payload: Record<string, unknown>,
) => string;

const CLIENT_ID = 'test-google-client-id';

function nowPlus(seconds: number): Date {
  return new Date(Date.now() + seconds * 1000);
}

function expectAppErrorStatus(fn: () => unknown, status: number): void {
  try {
    fn();
    throw new Error(`expected AppError(${status})`);
  } catch (e: unknown) {
    expect(e).toBeInstanceOf(AppError);
    expect((e as AppError).status).toBe(status);
  }
}

describe('GoogleSsoAdapter.validateAndExtractIdentity', () => {
  it('valid token → extracts email, sub, name', () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      iss: 'https://accounts.google.com',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      email: 'USER@Example.com',
      email_verified: true,
      sub: 'sub-1',
      name: 'User Name',
    });

    const identity = adapter.validateAndExtractIdentity({
      idToken,
      expectedNonce: 'n1',
      now: new Date(),
    });

    expect(identity).toEqual({ email: 'user@example.com', sub: 'sub-1', name: 'User Name' });
  });

  it('issuer mismatch → 401', () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      iss: 'https://issuer.example.com',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      email: 'a@example.com',
      email_verified: true,
      sub: 'sub-1',
    });

    expectAppErrorStatus(
      () => adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() }),
      401,
    );
  });

  it('audience mismatch → 401', () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      iss: 'https://accounts.google.com',
      aud: 'other-client',
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      email: 'a@example.com',
      email_verified: true,
      sub: 'sub-1',
    });

    expectAppErrorStatus(
      () => adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() }),
      401,
    );
  });

  it('expired exp → 401', () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      iss: 'https://accounts.google.com',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) - 1,
      nonce: 'n1',
      email: 'a@example.com',
      email_verified: true,
      sub: 'sub-1',
    });

    expectAppErrorStatus(
      () => adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: nowPlus(0) }),
      401,
    );
  });

  it('nonce mismatch → 401', () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      iss: 'https://accounts.google.com',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      email: 'a@example.com',
      email_verified: true,
      sub: 'sub-1',
    });

    expectAppErrorStatus(
      () => adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n2', now: new Date() }),
      401,
    );
  });

  it('email_verified === false → 403', () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      iss: 'https://accounts.google.com',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      email: 'a@example.com',
      email_verified: false,
      sub: 'sub-1',
    });

    expectAppErrorStatus(
      () => adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() }),
      403,
    );
  });

  it('email_verified missing → 403', () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      iss: 'https://accounts.google.com',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      email: 'a@example.com',
      sub: 'sub-1',
    });

    expectAppErrorStatus(
      () => adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() }),
      403,
    );
  });

  it('email claim missing → 401', () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      iss: 'https://accounts.google.com',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      email_verified: true,
      sub: 'sub-1',
    });

    expectAppErrorStatus(
      () => adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() }),
      401,
    );
  });

  it('sub claim missing → 401', () => {
    const adapter = new GoogleSsoAdapter(CLIENT_ID, 'secret');
    const idToken = buildFakeIdToken({
      iss: 'https://accounts.google.com',
      aud: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 60,
      nonce: 'n1',
      email: 'a@example.com',
      email_verified: true,
    });

    expectAppErrorStatus(
      () => adapter.validateAndExtractIdentity({ idToken, expectedNonce: 'n1', now: new Date() }),
      401,
    );
  });
});
