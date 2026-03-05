import type {
  SsoIdentityPayload,
  SsoProviderAdapter,
  SsoTokenExchangeResult,
} from '../../src/modules/auth/sso/sso-provider.interface';
import { AuthErrors } from '../../src/modules/auth/auth.errors';

/**
 * Test-only adapter wrapper.
 *
 * WHY:
 * - Keeps E2E tests network-free (no real OAuth token exchange).
 * - E2E fixtures use an unsigned JWT (alg:'none'), so real JWKS signature verification
 *   would always fail after Stage A1.
 * - We still validate nonce + required claims so the callback flow remains meaningful.
 *
 * SECURITY:
 * - This bypass exists only in test code and is never shipped to production.
 */
export class FakeSsoAdapter implements SsoProviderAdapter {
  readonly providerKey: 'google' | 'microsoft';

  private nextExchange: SsoTokenExchangeResult | Error | null = null;

  constructor(private readonly real: SsoProviderAdapter) {
    this.providerKey = real.providerKey as 'google' | 'microsoft';
  }

  buildAuthorizationUrl(input: { redirectUri: string; state: string; nonce: string }): string {
    return this.real.buildAuthorizationUrl(input);
  }

  willSucceed(result: SsoTokenExchangeResult): void {
    this.nextExchange = result;
  }

  willFail(error: Error): void {
    this.nextExchange = error;
  }

  exchangeAuthorizationCode(_input: {
    code: string;
    redirectUri: string;
  }): Promise<SsoTokenExchangeResult> {
    const next = this.nextExchange;
    this.nextExchange = null;

    if (!next) return Promise.reject(new Error('FakeSsoAdapter: no exchange result configured'));
    if (next instanceof Error) return Promise.reject(next);
    return Promise.resolve(next);
  }

  async validateAndExtractIdentity(input: {
    idToken: string;
    expectedNonce: string;
    now: Date;
  }): Promise<SsoIdentityPayload> {
    // Unit tests mock jose and validate real adapter crypto behavior.
    // E2E tests use alg:'none' idTokens → decode + validate minimal claims here.
    if (process.env.NODE_ENV === 'test') {
      const payload = decodeJwtPayloadUnsafe(input.idToken);

      if (payload.nonce !== input.expectedNonce) {
        throw AuthErrors.ssoTokenValidationFailed({ reason: 'nonce_mismatch' });
      }

      const sub = typeof payload.sub === 'string' ? payload.sub : null;
      if (!sub) {
        throw AuthErrors.ssoTokenValidationFailed({ reason: 'sub_missing' });
      }

      const email = resolveEmailForProvider(this.providerKey, payload);

      if (this.providerKey === 'google') {
        if (payload.email_verified !== true) {
          throw AuthErrors.ssoEmailNotVerified({ reason: 'email_not_verified' });
        }
      }

      const name = typeof payload.name === 'string' ? payload.name : undefined;

      return {
        email: email.toLowerCase(),
        sub,
        ...(name ? { name } : {}),
      };
    }

    // Non-test environments must use real signature verification + issuer/aud enforcement.
    return this.real.validateAndExtractIdentity(input);
  }
}

function decodeJwtPayloadUnsafe(idToken: string): Record<string, unknown> {
  const parts = idToken.split('.');
  if (parts.length < 2) throw new Error('invalid_jwt');

  const raw = Buffer.from(parts[1], 'base64url').toString('utf8');
  const parsed = JSON.parse(raw) as unknown;

  if (!parsed || typeof parsed !== 'object') throw new Error('invalid_jwt_payload');
  return parsed as Record<string, unknown>;
}

function resolveEmailForProvider(
  providerKey: 'google' | 'microsoft',
  payload: Record<string, unknown>,
): string {
  if (providerKey === 'google') {
    const email = typeof payload.email === 'string' ? payload.email : null;
    if (!email) throw AuthErrors.ssoTokenValidationFailed({ reason: 'email_missing' });
    return email;
  }

  // Microsoft fallback chain (mirrors real adapter behavior).
  const candidates = ['email', 'preferred_username', 'upn'] as const;
  for (const key of candidates) {
    const val = payload[key];
    if (typeof val === 'string' && val.includes('@')) return val;
  }

  throw AuthErrors.ssoTokenValidationFailed({ reason: 'email_missing' });
}
