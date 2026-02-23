/**
 * backend/src/modules/auth/sso/microsoft/microsoft-sso.adapter.ts
 *
 * WHY:
 * - Implements SsoProviderAdapter for Microsoft/Entra ID OAuth/OIDC.
 * - Multi-tenant: issuer derived from tid claim (locked spec requirement).
 *
 * RULES:
 * - Never log raw tokens.
 * - No email_verified check (locked: Microsoft has no reliable equivalent).
 */

import type {
  SsoIdentityPayload,
  SsoProviderAdapter,
  SsoTokenExchangeResult,
} from '../sso-provider.interface';
import { parseJwt } from '../jwt';
import { AuthErrors } from '../../auth.errors';

const MICROSOFT_AUTH_BASE = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
const MICROSOFT_TOKEN_ENDPOINT = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';

function microsoftIssuer(tid: string): string {
  return `https://login.microsoftonline.com/${tid}/v2.0`;
}

export class MicrosoftSsoAdapter implements SsoProviderAdapter {
  readonly providerKey = 'microsoft' as const;

  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
  ) {}

  buildAuthorizationUrl(input: { redirectUri: string; state: string; nonce: string }): string {
    const url = new URL(MICROSOFT_AUTH_BASE);
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', input.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('response_mode', 'query');
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
      code: input.code,
      client_id: this.clientId,
      client_secret: this.clientSecret,
      redirect_uri: input.redirectUri,
      grant_type: 'authorization_code',
    });

    // NOTE: In E2E tests we inject a test adapter that overrides this method.
    const res = await fetch(MICROSOFT_TOKEN_ENDPOINT, {
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

  validateAndExtractIdentity(input: {
    idToken: string;
    expectedNonce: string;
    now: Date;
  }): SsoIdentityPayload {
    let payload: Record<string, unknown>;
    try {
      payload = parseJwt(input.idToken).payload;
    } catch {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'jwt_parse_failed' });
    }

    const tid = getString(payload, 'tid');
    if (!tid) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'tid_missing' });
    }

    if (payload.iss !== microsoftIssuer(tid)) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'issuer_mismatch' });
    }
    if (payload.aud !== this.clientId) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'audience_mismatch' });
    }
    if (typeof payload.exp !== 'number' || payload.exp * 1000 <= input.now.getTime()) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'token_expired' });
    }
    if (payload.nonce !== input.expectedNonce) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'nonce_mismatch' });
    }

    const email =
      getString(payload, 'email') ??
      getString(payload, 'preferred_username') ??
      getString(payload, 'upn');

    if (!email) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'email_missing' });
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

// ── internal helpers ────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function getString(obj: Record<string, unknown>, key: string): string | undefined {
  const v = obj[key];
  return typeof v === 'string' && v.length ? v : undefined;
}
