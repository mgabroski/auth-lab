/**
 * backend/src/modules/auth/sso/sso-provider.interface.ts
 *
 * WHY:
 * - OCP: adding a new provider (LinkedIn, Apple) must not touch existing code.
 * - DIP: flows depend on this abstraction, not on concrete provider functions.
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
  /**
   * String key used in routes and registry lookup.
   * Keep as string for true OCP (no interface edits when adding providers).
   */
  readonly providerKey: string;

  buildAuthorizationUrl(input: { redirectUri: string; state: string; nonce: string }): string;

  exchangeAuthorizationCode(input: {
    code: string;
    redirectUri: string;
  }): Promise<SsoTokenExchangeResult>;

  /**
   * Cryptographically verify the ID token and extract a normalized identity.
   *
   * NOTE: This is async because JWKS verification is async (jose).
   */
  validateAndExtractIdentity(input: {
    idToken: string;
    expectedNonce: string;
    now: Date;
  }): Promise<SsoIdentityPayload>;
}
