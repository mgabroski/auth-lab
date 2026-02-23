/**
 * backend/src/modules/auth/sso/microsoft/microsoft-sso.provider.ts
 *
 * WHY:
 * - Encapsulate Microsoft OAuth/OIDC token exchange + ID token claim extraction/validation.
 * - Microsoft is multi-tenant (Brick 10 locked): issuer is derived from tid.
 *
 * RULES:
 * - Never log/store raw tokens.
 * - Validate issuer/audience/exp/nonce.
 * - No email_verified requirement (locked).
 */

import { parseJwt } from '../jwt';
import { AuthErrors } from '../../auth.errors';

export type MicrosoftTokenExchangeResult = {
  idToken: string;
};

export type MicrosoftIdentity = {
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

export async function exchangeMicrosoftAuthorizationCode(params: {
  code: string;
  redirectUri: string;
  clientId: string;
  clientSecret: string;
}): Promise<MicrosoftTokenExchangeResult> {
  // NOTE: In E2E tests this function is mocked. No external HTTP in tests.
  const body = new URLSearchParams();
  body.set('code', params.code);
  body.set('client_id', params.clientId);
  body.set('client_secret', params.clientSecret);
  body.set('redirect_uri', params.redirectUri);
  body.set('grant_type', 'authorization_code');

  const res = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
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

export function validateAndExtractMicrosoftIdentity(params: {
  idToken: string;
  expectedAudience: string; // MICROSOFT_CLIENT_ID
  expectedNonce: string;
  now: Date;
}): MicrosoftIdentity {
  let payload: Record<string, unknown>;
  try {
    payload = parseJwt(params.idToken).payload;
  } catch {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'jwt_parse_failed' });
  }

  const tid = payload.tid;
  if (typeof tid !== 'string' || !tid.length) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'tid_missing' });
  }

  // LOCKED: issuer derived from tid
  const expectedIssuer = `https://login.microsoftonline.com/${tid}/v2.0`;
  if (payload.iss !== expectedIssuer) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'issuer_mismatch' });
  }

  if (payload.aud !== params.expectedAudience) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'audience_mismatch' });
  }

  const exp = payload.exp;
  if (typeof exp !== 'number') {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'exp_missing' });
  }

  if (exp * 1000 <= params.now.getTime()) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'token_expired' });
  }

  if (payload.nonce !== params.expectedNonce) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'nonce_mismatch' });
  }

  const emailCandidate =
    typeof payload.email === 'string'
      ? payload.email
      : typeof payload.preferred_username === 'string'
        ? payload.preferred_username
        : typeof payload.upn === 'string'
          ? payload.upn
          : undefined;

  if (!emailCandidate || !emailCandidate.length) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'email_missing' });
  }

  const sub = payload.sub;
  if (typeof sub !== 'string' || !sub.length) {
    throw AuthErrors.ssoTokenValidationFailed({ reason: 'sub_missing' });
  }

  const name = typeof payload.name === 'string' && payload.name.length ? payload.name : undefined;

  return {
    email: emailCandidate.toLowerCase(),
    sub,
    ...(name ? { name } : {}),
  };
}
