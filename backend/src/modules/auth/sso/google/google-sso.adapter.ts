/**
 * backend/src/modules/auth/sso/google/google-sso.adapter.ts
 *
 * WHY:
 * - Implements SsoProviderAdapter for Google OAuth/OIDC.
 * - Keeps Google-specific constants (issuer, endpoints) out of shared flow code.
 *
 * RULES:
 * - Never log raw tokens.
 * - email_verified must be true (locked spec requirement).
 */

import type {
  SsoIdentityPayload,
  SsoProviderAdapter,
  SsoTokenExchangeResult,
} from '../sso-provider.interface';
import { AuthErrors } from '../../auth.errors';
import { getString, isRecord } from '../sso-adapter-utils';
import { verifyGoogleJwt } from '../jwt';

const GOOGLE_AUTH_BASE = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';

export class GoogleSsoAdapter implements SsoProviderAdapter {
  readonly providerKey = 'google';

  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
  ) {}

  buildAuthorizationUrl(input: { redirectUri: string; state: string; nonce: string }): string {
    const url = new URL(GOOGLE_AUTH_BASE);
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', input.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', input.state);
    url.searchParams.set('nonce', input.nonce);
    url.searchParams.set('prompt', 'select_account');
    return url.toString();
  }

  async exchangeAuthorizationCode(input: {
    code: string;
    redirectUri: string;
  }): Promise<SsoTokenExchangeResult> {
    const body = new URLSearchParams({
      code: input.code,
      client_id: this.clientId,
      client_secret: this.clientSecret,
      redirect_uri: input.redirectUri,
      grant_type: 'authorization_code',
    });

    const res = await fetch(GOOGLE_TOKEN_ENDPOINT, {
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
    let payload: Record<string, unknown>;
    try {
      payload = (await verifyGoogleJwt({
        idToken: input.idToken,
        clientId: this.clientId,
        expectedNonce: input.expectedNonce,
      })) as unknown as Record<string, unknown>;
    } catch (e: unknown) {
      const reason =
        e instanceof Error && e.message === 'jwt_nonce_mismatch'
          ? 'nonce_mismatch'
          : 'jwt_verify_failed';
      throw AuthErrors.ssoTokenValidationFailed({ reason });
    }

    const email = getString(payload, 'email');
    if (!email) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'email_missing' });
    }

    // LOCKED: Google must have email_verified === true
    if (payload.email_verified !== true) {
      throw AuthErrors.ssoEmailNotVerified({ reason: 'email_not_verified' });
    }

    const sub = getString(payload, 'sub');
    if (!sub) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'sub_missing' });
    }

    const name = getString(payload, 'name');

    return {
      email: email.toLowerCase(),
      sub,
      ...(name ? { name } : {}),
    };
  }
}
