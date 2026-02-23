/**
 * backend/src/modules/auth/sso/sso-provider.interface.ts
 *
 * WHY:
 * - OCP: adding a new provider must not require editing flow or URL builder.
 * - DIP: flows depend on this abstraction, not on provider-specific functions.
 *
 * RULES:
 * - No HTTP framework imports here.
 * - Never log/store raw tokens inside adapters.
 */

export type SsoIdentityPayload = {
  /** Normalized lowercase email. Required. */
  email: string;
  /** Display name. Optional. */
  name?: string;
  /** Provider subject identifier (sub). Required. */
  sub: string;
};

export type SsoTokenExchangeResult = {
  idToken: string;
};

export interface SsoProviderAdapter {
  readonly providerKey: 'google' | 'microsoft';

  buildAuthorizationUrl(input: { redirectUri: string; state: string; nonce: string }): string;

  exchangeAuthorizationCode(input: {
    code: string;
    redirectUri: string;
  }): Promise<SsoTokenExchangeResult>;

  validateAndExtractIdentity(input: {
    idToken: string;
    expectedNonce: string;
    now: Date;
  }): SsoIdentityPayload;
}
