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

  googleClientId: string;
  microsoftClientId: string;
}): string {
  const { state, nonce } = buildEncryptedSsoState({
    encryptionService: input.encryptionService,
    provider: input.provider,
    tenantKey: input.tenantKey,
    requestId: input.requestId,
    returnTo: input.returnTo,
  });

  const redirectUri = callbackUrl(input.redirectBaseUrl, input.provider);

  if (input.provider === 'google') {
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.searchParams.set('client_id', input.googleClientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('prompt', 'select_account');
    return url.toString();
  }

  const url = new URL('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
  url.searchParams.set('client_id', input.microsoftClientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('response_mode', 'query');
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  return url.toString();
}
