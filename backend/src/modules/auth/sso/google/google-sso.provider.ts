/**
 * backend/src/modules/auth/sso/google/google-sso.provider.ts
 *
 * WHY:
 * - Encapsulate Google OAuth/OIDC token exchange + ID token claim extraction/validation.
 * - Tests mock exchange; we still keep the module boundary clean.
 *
 * RULES:
 * - Never log/store raw tokens.
 * - Validate issuer/audience/exp/nonce/email_verified.
 * - Return only the fields needed for provisioning.
 */

import { parseJwt } from '../jwt';
import { AuthErrors } from '../../auth.errors';

export type GoogleTokenExchangeResult = {
  idToken: string;
};

export type GoogleIdentity = {
  email: string;
  name?: string;
  sub: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function getString(obj: Record<string, unknown>, key: string): string | undefined {
  const v = obj[key];
  return typeof v === 'string' && v.length ? v : undefined;
}

export async function exchangeGoogleAuthorizationCode(params: {
  code: string;
  redirectUri: string;
  clientId: string;
  clientSecret: string;
}): Promise<GoogleTokenExchangeResult> {
  // NOTE: In E2E tests this function is mocked. No external HTTP in tests.
  const body = new URLSearchParams();
  body.set('code', params.code);
  body.set('client_id', params.clientId);
  body.set('client_secret', params.clientSecret);
  body.set('redirect_uri', params.redirectUri);
  body.set('grant_type', 'authorization_code');

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!res.ok) {
    throw AuthErrors.ssoStateInvalid({ reason: 'token_exchange_failed' });
  }

  const json: unknown = await res.json();
  if (!isRecord(json)) {
    throw AuthErrors.ssoStateInvalid({ reason: 'token_exchange_invalid_json' });
  }

  const idToken = getString(json, 'id_token');
  if (!idToken) {
    throw AuthErrors.ssoStateInvalid({ reason: 'missing_id_token' });
  }

  return { idToken };
}

export function validateAndExtractGoogleIdentity(params: {
  idToken: string;
  expectedIssuer: string; // https://accounts.google.com
  expectedAudience: string; // GOOGLE_CLIENT_ID
  expectedNonce: string;
  now: Date;
}): GoogleIdentity {
  let payload: Record<string, unknown>;
  try {
    payload = parseJwt(params.idToken).payload;
  } catch {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'jwt_parse_failed' });
  }

  const iss = payload.iss;
  const aud = payload.aud;
  const exp = payload.exp;
  const nonce = payload.nonce;

  if (iss !== params.expectedIssuer) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'issuer_mismatch' });
  }

  if (aud !== params.expectedAudience) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'audience_mismatch' });
  }

  if (typeof exp !== 'number') {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'exp_missing' });
  }

  const expMs = exp * 1000;
  if (expMs <= params.now.getTime()) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'token_expired' });
  }

  if (nonce !== params.expectedNonce) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'nonce_mismatch' });
  }

  const email = payload.email;
  if (typeof email !== 'string' || !email.length) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'email_missing' });
  }

  const emailVerified = payload.email_verified;
  if (emailVerified !== true) {
    // LOCKED: Google must have email_verified === true
    throw AuthErrors.ssoEmailNotVerified({ reason: 'email_not_verified' });
  }

  const sub = payload.sub;
  if (typeof sub !== 'string' || !sub.length) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'sub_missing' });
  }

  const name = typeof payload.name === 'string' && payload.name.length ? payload.name : undefined;

  return {
    email: email.toLowerCase(),
    sub,
    ...(name ? { name } : {}),
  };
}
