/**
 * backend/src/modules/auth/helpers/sso-state-validate.ts
 *
 * WHY:
 * - Brick 10: callback must validate encrypted state integrity + expiry + binding.
 *
 * RULES:
 * - Throw AuthErrors.ssoStateInvalid (400) for malformed/expired/mismatched state.
 * - Never log raw state.
 */

import type { EncryptionService } from '../../../shared/security/encryption';
import { AuthErrors } from '../auth.errors';
import type { SsoProvider, SsoStatePayload } from './sso-state';
import { isRecord, getString, getNumber } from '../sso/sso-adapter-utils';

export function decryptAndValidateSsoState(params: {
  encryptionService: EncryptionService;
  encryptedState: string;
  provider: SsoProvider;
  tenantKey: string;
  now: Date;
}): SsoStatePayload {
  let plaintext: string;
  try {
    plaintext = params.encryptionService.decrypt(params.encryptedState);
  } catch {
    throw AuthErrors.ssoStateInvalid({ reason: 'decrypt_failed' });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext) as unknown;
  } catch {
    throw AuthErrors.ssoStateInvalid({ reason: 'json_parse_failed' });
  }

  if (!isRecord(parsed)) {
    throw AuthErrors.ssoStateInvalid({ reason: 'payload_not_object' });
  }

  const provider = getString(parsed, 'provider');
  const tenantKey = getString(parsed, 'tenantKey');
  const nonce = getString(parsed, 'nonce');
  const requestId = getString(parsed, 'requestId');
  const issuedAt = getNumber(parsed, 'issuedAt');
  const expiresAt = getNumber(parsed, 'expiresAt');
  const redirectUri = getString(parsed, 'redirectUri');
  const returnToRaw = parsed['returnTo'];

  if (provider !== params.provider) {
    throw AuthErrors.ssoStateInvalid({ reason: 'provider_mismatch' });
  }
  if (tenantKey !== params.tenantKey) {
    throw AuthErrors.ssoStateInvalid({ reason: 'tenant_mismatch' });
  }
  if (!nonce) {
    throw AuthErrors.ssoStateInvalid({ reason: 'nonce_missing' });
  }
  if (!issuedAt) {
    throw AuthErrors.ssoStateInvalid({ reason: 'issued_missing' });
  }
  if (!expiresAt) {
    throw AuthErrors.ssoStateInvalid({ reason: 'expires_missing' });
  }
  if (expiresAt <= params.now.getTime()) {
    throw AuthErrors.ssoStateInvalid({ reason: 'state_expired' });
  }
  if (!requestId) {
    throw AuthErrors.ssoStateInvalid({ reason: 'requestId_missing' });
  }
  if (!redirectUri) {
    throw AuthErrors.ssoStateInvalid({ reason: 'redirectUri_missing' });
  }

  const payload: SsoStatePayload = {
    provider: params.provider,
    tenantKey: params.tenantKey,
    nonce,
    issuedAt,
    expiresAt,
    requestId,
    redirectUri,
    ...(typeof returnToRaw === 'string' && returnToRaw.length ? { returnTo: returnToRaw } : {}),
  };

  return payload;
}
