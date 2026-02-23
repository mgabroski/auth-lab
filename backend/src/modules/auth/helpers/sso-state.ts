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
 * - Nonce is embedded inside the encrypted payload (and also sent as `nonce=`).
 *
 * RULES:
 * - Never log the raw state.
 * - Keep payload minimal.
 */

import { randomBytes } from 'node:crypto';
import type { EncryptionService } from '../../../shared/security/encryption';

export type SsoProvider = 'google' | 'microsoft';

export type SsoStatePayload = {
  provider: SsoProvider;
  tenantKey: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  requestId: string;
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

export function buildEncryptedSsoState(input: {
  encryptionService: EncryptionService;
  provider: SsoProvider;
  tenantKey: string;
  requestId: string;
  returnTo?: string;
  now?: Date;
}): { state: string; nonce: string; payload: SsoStatePayload } {
  const now = input.now ?? new Date();
  const issuedAt = now.getTime();
  const expiresAt = issuedAt + STATE_TTL_MS;
  const nonce = generateNonce();

  const payload: SsoStatePayload = {
    provider: input.provider,
    tenantKey: input.tenantKey,
    nonce,
    issuedAt,
    expiresAt,
    requestId: input.requestId,
    ...(input.returnTo ? { returnTo: input.returnTo } : {}),
  };

  const plaintext = JSON.stringify(payload);
  const state = input.encryptionService.encrypt(plaintext);

  return { state, nonce, payload };
}
