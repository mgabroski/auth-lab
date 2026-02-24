/**
 * backend/src/modules/auth/sso/jwt.ts
 *
 * WHY:
 * - Lightweight JWT parsing for OIDC ID tokens.
 * - Brick 10 requires validating claims (iss/aud/exp/nonce/etc.).
 *
 * RULES:
 * - Do NOT log tokens.
 * - It is used with mocked token exchange in tests.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ⚠️  PRODUCTION GAP: JWT SIGNATURES ARE NOT VERIFIED
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * This file ONLY parses and decodes the JWT. It does NOT verify the
 * cryptographic signature. In production, any well-formed token with
 * valid claims (iss, aud, exp, nonce) will be accepted, even if it
 * was not issued by Google or Microsoft.
 *
 * This was a deliberate lab decision. It MUST be resolved before shipping.
 *
 * HOW TO FIX — use the `jose` library (standard, maintained, Node.js native):
 *
 *   npm install jose
 *
 * Google:
 *   import { createRemoteJWKSet, jwtVerify } from 'jose';
 *
 *   const GOOGLE_JWKS = createRemoteJWKSet(
 *     new URL('https://www.googleapis.com/oauth2/v3/certs')
 *   );
 *
 *   const { payload } = await jwtVerify(idToken, GOOGLE_JWKS, {
 *     issuer: 'https://accounts.google.com',
 *     audience: clientId,
 *   });
 *
 * Microsoft:
 *   const MICROSOFT_JWKS = createRemoteJWKSet(
 *     new URL('https://login.microsoftonline.com/common/discovery/v2.0/keys')
 *   );
 *
 *   const { payload } = await jwtVerify(idToken, MICROSOFT_JWKS, {
 *     issuer: `https://login.microsoftonline.com/${tid}/v2.0`, // tid from payload
 *     audience: clientId,
 *   });
 *
 * JWKS responses should be cached (jose does this automatically via
 * createRemoteJWKSet). Do not fetch the JWKS on every request.
 *
 * Once signature verification is in place:
 * - Remove parseJwt() from the adapter validate methods.
 * - Replace the manual iss/aud/exp checks — jwtVerify handles them.
 * - Keep the nonce check: jwtVerify does NOT check nonce by default.
 *   Pass { typ: 'JWT' } and check payload.nonce manually after verify.
 * - FakeSsoAdapter in tests continues to work because it skips
 *   exchangeAuthorizationCode and the token is only parsed, not remotely verified.
 *   You will need to sign fake tokens with a test key or mock jwtVerify.
 * ─────────────────────────────────────────────────────────────────────────────
 */

function base64UrlToJson(input: string): unknown {
  const padded = input
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(input.length / 4) * 4, '=');
  const raw = Buffer.from(padded, 'base64').toString('utf8');
  return JSON.parse(raw) as unknown;
}

export type JwtParts = { header: Record<string, unknown>; payload: Record<string, unknown> };

export function parseJwt(token: string): JwtParts {
  const parts = token.split('.');
  if (parts.length < 2) {
    throw new Error('invalid_jwt');
  }
  const header = base64UrlToJson(parts[0]);
  const payload = base64UrlToJson(parts[1]);

  if (!header || typeof header !== 'object') throw new Error('invalid_jwt_header');
  if (!payload || typeof payload !== 'object') throw new Error('invalid_jwt_payload');

  return {
    header: header as Record<string, unknown>,
    payload: payload as Record<string, unknown>,
  };
}
