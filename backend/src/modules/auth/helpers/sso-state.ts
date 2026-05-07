/**
 * backend/src/modules/auth/helpers/sso-state.ts
 *
 * WHY:
 * - Brick 10 uses OAuth/OIDC redirects.
 * - We must carry tenant-scoped state across the provider round-trip with:
 *   integrity + expiry + tenant/provider binding.
 * - We avoid Redis storage: everything is embedded in encrypted state.
 *
 * FORMAT:
 * - State is JSON -> AES-256-GCM encrypted via EncryptionService.
 * - Nonce and PKCE code verifier are embedded inside the encrypted payload.
 * - Only the nonce and PKCE code challenge are sent to the authorization URL.
 *
 * RULES:
 * - Never log the raw state.
 * - Keep payload minimal.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { EncryptionService } from '../../../shared/security/encryption';

export type SsoProvider = 'google' | 'microsoft';

export type SsoStatePayload = {
  provider: SsoProvider;
  tenantKey: string;
  nonce: string;
  /**
   * OAuth 2.1 / RFC 9700 defense-in-depth for the authorization-code flow.
   * Stored only inside the encrypted, short-lived sso-state cookie.
   * Sent to the provider only during token exchange.
   */
  pkceCodeVerifier: string;
  issuedAt: number;
  expiresAt: number;
  requestId: string;
  /**
   * WHY: The redirectUri is embedded in the encrypted state at SSO start time.
   * The callback uses this value to reconstruct the exact URI it sends to the
   * provider for token exchange — instead of re-deriving it from a global
   * SSO_REDIRECT_BASE_URL config value.
   *
   * This makes the callback tenant-aware: each tenant's subdomain produces
   * its own redirect URI (e.g. goodwill-ca.hubins.com vs acme.hubins.com),
   * and the callback validates that the URI it constructs matches what was
   * registered with the provider at start time.
   *
   * Without this, a single global redirectBaseUrl would make all tenants
   * share one OAuth registered redirect URI — which breaks in multi-tenant
   * setups where each tenant may have its own OAuth app or subdomain.
   */
  redirectUri: string;
  returnTo?: string;
};

// 10 minutes is enough for the browser/provider roundtrip.
const STATE_TTL_MS = 10 * 60 * 1000;

function base64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function generateNonce(): string {
  return base64Url(randomBytes(16));
}

export function generatePkceCodeVerifier(): string {
  return base64Url(randomBytes(32));
}

export function buildPkceCodeChallenge(codeVerifier: string): string {
  return base64Url(createHash('sha256').update(codeVerifier).digest());
}

export function buildEncryptedSsoState(input: {
  encryptionService: EncryptionService;
  provider: SsoProvider;
  tenantKey: string;
  requestId: string;
  redirectUri: string;
  returnTo?: string;
  now?: Date;
}): { state: string; nonce: string; payload: SsoStatePayload } {
  const now = input.now ?? new Date();
  const issuedAt = now.getTime();
  const expiresAt = issuedAt + STATE_TTL_MS;
  const nonce = generateNonce();
  const pkceCodeVerifier = generatePkceCodeVerifier();

  const payload: SsoStatePayload = {
    provider: input.provider,
    tenantKey: input.tenantKey,
    nonce,
    pkceCodeVerifier,
    issuedAt,
    expiresAt,
    requestId: input.requestId,
    redirectUri: input.redirectUri,
    ...(input.returnTo ? { returnTo: input.returnTo } : {}),
  };

  const plaintext = JSON.stringify(payload);
  const state = input.encryptionService.encrypt(plaintext);

  return { state, nonce, payload };
}
