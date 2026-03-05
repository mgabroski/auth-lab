/**
 * backend/src/modules/auth/sso/jwt.ts
 *
 * WHY:
 * - Cryptographically verifies OIDC ID tokens (SSO boundary).
 * - Prevents accepting forged / tampered JWTs (P0).
 *
 * RULES:
 * - Never log raw tokens.
 * - JWKS must be remotely fetched with caching (jose handles caching).
 * - jwtVerify enforces iss/aud/exp; we still enforce nonce explicitly.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

export const GOOGLE_JWKS = createRemoteJWKSet(
  new URL('https://www.googleapis.com/oauth2/v3/certs'),
);

export const MICROSOFT_JWKS = createRemoteJWKSet(
  new URL('https://login.microsoftonline.com/common/discovery/v2.0/keys'),
);

export async function verifyGoogleJwt(params: {
  idToken: string;
  clientId: string;
  expectedNonce: string;
}): Promise<JWTPayload> {
  const { payload } = await jwtVerify(params.idToken, GOOGLE_JWKS, {
    issuer: 'https://accounts.google.com',
    audience: params.clientId,
  });

  // jose does not validate nonce by default.
  if (payload.nonce !== params.expectedNonce) {
    throw new Error('jwt_nonce_mismatch');
  }

  return payload;
}

/**
 * Microsoft issuer is tenant-specific (tid). We must validate against the correct
 * issuer URL, which requires tid. (locked spec requirement)
 */
export async function verifyMicrosoftJwt(params: {
  idToken: string;
  clientId: string;
  expectedNonce: string;
  tid: string;
}): Promise<JWTPayload> {
  const { payload } = await jwtVerify(params.idToken, MICROSOFT_JWKS, {
    issuer: `https://login.microsoftonline.com/${params.tid}/v2.0`,
    audience: params.clientId,
  });

  if (payload.nonce !== params.expectedNonce) {
    throw new Error('jwt_nonce_mismatch');
  }

  return payload;
}

/**
 * Unsafe helper: decode JWT payload WITHOUT verifying signature.
 *
 * WHY:
 * - For Microsoft, we need `tid` to build the issuer string that jwtVerify()
 *   will enforce. The `tid` value itself is not trusted; it only influences the
 *   expected issuer which is cryptographically enforced by jwtVerify.
 */
export function decodeJwtPayloadUnsafe(idToken: string): Record<string, unknown> {
  const parts = idToken.split('.');
  if (parts.length < 2) throw new Error('invalid_jwt');

  const rawPayload = Buffer.from(parts[1], 'base64url').toString('utf8');
  const payload = JSON.parse(rawPayload) as unknown;

  if (!payload || typeof payload !== 'object') throw new Error('invalid_jwt_payload');

  return payload as Record<string, unknown>;
}
