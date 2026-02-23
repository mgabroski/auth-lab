/**
 * backend/src/modules/auth/helpers/sso-authorize-url.ts
 *
 * WHY:
 * - Single place to build provider authorization URLs.
 * - Keeps auth.service/controller free of URL construction details.
 *
 * RULES:
 * - Always include both `state=` and `nonce=` in the authorization URL.
 * - Do not log the resulting URL (it contains encrypted state).
 */

import type { EncryptionService } from '../../../shared/security/encryption';
import { buildEncryptedSsoState, type SsoProvider } from './sso-state';
import type { SsoProviderRegistry } from '../sso/sso-provider-registry';

function callbackUrl(redirectBaseUrl: string, provider: SsoProvider): string {
  return `${redirectBaseUrl.replace(/\/+$/g, '')}/auth/sso/${provider}/callback`;
}

export function buildSsoAuthorizationUrl(input: {
  provider: SsoProvider;
  tenantKey: string;
  requestId: string;
  returnTo?: string;

  encryptionService: EncryptionService;
  redirectBaseUrl: string;

  providerRegistry: SsoProviderRegistry;
}): string {
  const { state, nonce } = buildEncryptedSsoState({
    encryptionService: input.encryptionService,
    provider: input.provider,
    tenantKey: input.tenantKey,
    requestId: input.requestId,
    returnTo: input.returnTo,
  });

  const redirectUri = callbackUrl(input.redirectBaseUrl, input.provider);

  const adapter = input.providerRegistry.getOrThrow(input.provider);
  return adapter.buildAuthorizationUrl({ redirectUri, state, nonce });
}
