/**
 * backend/src/modules/auth/sso/local-oidc/local-oidc-sso.adapter.ts
 *
 * WHY:
 * - Closes the Phase 6/7 "SSO not proven in CI" gap from the final audit.
 * - The FakeSsoAdapter used in backend unit/E2E tests bypasses real JWKS fetch
 *   and JWT signature verification. Those tests prove flow logic but NOT the
 *   actual JWT cryptographic path.
 * - This adapter talks to the CI-local OIDC server (infra/oidc-server/) which
 *   issues real RS256-signed JWTs from a real JWKS endpoint. Using this adapter
 *   in the Playwright CI job means jose jwtVerify() runs the full path:
 *     JWKS HTTP fetch → RSA signature check → iss/aud/exp → nonce enforcement.
 *
 * RULES:
 * - CI only. Never registered in production DI wiring.
 * - The providerKey ('google' or 'microsoft') is injected at construction so
 *   one adapter class serves both providers in CI. The local OIDC server is
 *   provider-agnostic; the backend only cares about the interface contract.
 * - Token validation uses the real jose library (same path as the real adapters).
 *   The only difference is the JWKS URL and issuer — both pointed at localhost.
 * - email_verified is enforced for providerKey='google' (matches production rule).
 *   Microsoft check is intentionally omitted (same as MicrosoftSsoAdapter).
 * - Never log raw tokens.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type {
  SsoIdentityPayload,
  SsoProviderAdapter,
  SsoTokenExchangeResult,
} from '../sso-provider.interface';
import { AuthErrors } from '../../auth.errors';
import { getString, isRecord } from '../sso-adapter-utils';

export type LocalOidcAdapterConfig = {
  /**
   * Must match what the local OIDC server has as LOCAL_OIDC_CLIENT_ID.
   * Used as the `aud` claim in token validation.
   */
  clientId: string;
  /**
   * The base URL of the local OIDC server reachable from the backend container.
   * Example: http://local-oidc:9998  (Docker network)
   * Example: http://localhost:9998   (host-run)
   */
  issuerUrl: string;
  /**
   * Which provider key this adapter is registered under in the SsoProviderRegistry.
   * 'google' | 'microsoft' — determines which routes trigger this adapter and
   * whether email_verified is required.
   */
  providerKey: 'google' | 'microsoft';
};

export class LocalOidcSsoAdapter implements SsoProviderAdapter {
  readonly providerKey: string;

  private readonly clientId: string;
  private readonly issuerUrl: string;
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(config: LocalOidcAdapterConfig) {
    this.providerKey = config.providerKey;
    this.clientId = config.clientId;
    this.issuerUrl = config.issuerUrl.replace(/\/$/, '');
    this.jwks = createRemoteJWKSet(new URL(`${this.issuerUrl}/.well-known/jwks.json`));
  }

  buildAuthorizationUrl(input: { redirectUri: string; state: string; nonce: string }): string {
    // WHY: In CI the "authorization URL" is never actually navigated to. The
    // Playwright test uses POST /code on the OIDC server to get a code and then
    // calls the backend callback endpoint directly. This method must return a
    // structurally valid URL so the SSO start flow doesn't throw, but the URL
    // is not followed during CI testing.
    const url = new URL(`${this.issuerUrl}/authorize`);
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', input.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', input.state);
    url.searchParams.set('nonce', input.nonce);
    return url.toString();
  }

  async exchangeAuthorizationCode(input: {
    code: string;
    redirectUri: string;
  }): Promise<SsoTokenExchangeResult> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      client_id: this.clientId,
      client_secret: 'local-oidc-ci-secret', // local server doesn't validate the secret
      redirect_uri: input.redirectUri,
    });

    const res = await fetch(`${this.issuerUrl}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });

    if (!res.ok) {
      throw AuthErrors.ssoStateInvalid({ reason: 'token_exchange_failed' });
    }

    const json: unknown = await res.json();
    if (!isRecord(json)) {
      throw AuthErrors.ssoStateInvalid({ reason: 'token_exchange_invalid_json' });
    }

    const idToken = getString(json, 'id_token');
    if (!idToken) {
      throw AuthErrors.ssoStateInvalid({ reason: 'missing_id_token' });
    }

    return { idToken };
  }

  async validateAndExtractIdentity(input: {
    idToken: string;
    expectedNonce: string;
    now: Date;
  }): Promise<SsoIdentityPayload> {
    // WHY: This is the critical validation path this adapter exists to prove.
    // jose jwtVerify() fetches the JWKS from the local OIDC server, performs
    // RSA-256 signature verification, and enforces iss / aud / exp claims.
    // This is identical code to what the real Google/Microsoft adapters execute —
    // the only difference is which JWKS URL and issuer are targeted.
    let payload: JWTPayload;
    try {
      const result = await jwtVerify(input.idToken, this.jwks, {
        issuer: this.issuerUrl,
        audience: this.clientId,
      });
      payload = result.payload;
    } catch (e: unknown) {
      const reason =
        e instanceof Error && e.message === 'jwt_nonce_mismatch'
          ? 'nonce_mismatch'
          : 'jwt_verify_failed';
      throw AuthErrors.ssoTokenValidationFailed({ reason });
    }

    // Explicit nonce check (jose does not validate nonce by default)
    if (payload.nonce !== input.expectedNonce) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'nonce_mismatch' });
    }

    const claims = payload as Record<string, unknown>;

    const email = getString(claims, 'email');
    if (!email) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'email_missing' });
    }

    // Google-path requires email_verified === true (locked spec rule)
    if (this.providerKey === 'google' && claims['email_verified'] !== true) {
      throw AuthErrors.ssoEmailNotVerified({ reason: 'email_not_verified' });
    }

    const sub = getString(claims, 'sub');
    if (!sub) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'sub_missing' });
    }

    const name = getString(claims, 'name');

    return {
      email: email.toLowerCase(),
      sub,
      ...(name ? { name } : {}),
    };
  }
}
