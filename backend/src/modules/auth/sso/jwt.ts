/**
 * backend/src/modules/auth/sso/jwt.ts
 *
 * WHY:
 * - Lightweight JWT parsing for OIDC ID tokens.
 * - Brick 10 requires validating claims (iss/aud/exp/nonce/etc.).
 *
 * RULES:
 * - Do NOT log tokens.
 * - This parser does NOT verify signatures (out of scope for this lab).
 * - It is used with mocked token exchange in tests.
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
