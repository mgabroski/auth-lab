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
import { AuthErrors } from '../../auth.errors';
import { getString, isRecord } from '../sso-adapter-utils';
import { decodeJwtPayloadUnsafe, verifyMicrosoftJwt } from '../jwt';

const MICROSOFT_AUTH_BASE = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
const MICROSOFT_TOKEN_ENDPOINT = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';

// Helper: resolve email from Microsoft claim priority chain.
// Microsoft does not guarantee an email claim; preferred_username and upn are
// common alternatives in enterprise (Entra ID) tenants.
function resolveMicrosoftEmail(payload: Record<string, unknown>): string {
  const candidates = ['email', 'preferred_username', 'upn'] as const;
  for (const key of candidates) {
    const val = payload[key];
    if (typeof val === 'string' && val.includes('@')) return val;
  }
  throw AuthErrors.ssoTokenValidationFailed({ reason: 'email_missing' });
}

export class MicrosoftSsoAdapter implements SsoProviderAdapter {
  readonly providerKey = 'microsoft';

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

  async validateAndExtractIdentity(input: {
    idToken: string;
    expectedNonce: string;
    now: Date;
  }): Promise<SsoIdentityPayload> {
    // 1) Decode tid from unverified payload — needed to build issuer URL.
    //    This is safe: tid is only used to construct the expected issuer,
    //    which jwtVerify then cryptographically enforces.
    let rawPayload: Record<string, unknown>;
    try {
      rawPayload = decodeJwtPayloadUnsafe(input.idToken);
    } catch {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'jwt_parse_failed' });
    }

    const tid = getString(rawPayload, 'tid');
    if (!tid) {
      throw AuthErrors.ssoTokenValidationFailed({ reason: 'tid_missing' });
    }

    // 2) Cryptographic verification — jwtVerify enforces iss, aud, exp.
    let payload: Record<string, unknown>;
    try {
      payload = (await verifyMicrosoftJwt({
        idToken: input.idToken,
        clientId: this.clientId,
        expectedNonce: input.expectedNonce,
        tid,
      })) as unknown as Record<string, unknown>;
    } catch (e: unknown) {
      const reason =
        e instanceof Error && e.message === 'jwt_nonce_mismatch'
          ? 'nonce_mismatch'
          : 'jwt_verify_failed';
      throw AuthErrors.ssoTokenValidationFailed({ reason });
    }

    const email = resolveMicrosoftEmail(payload);

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
