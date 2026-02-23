import type {
  SsoIdentityPayload,
  SsoProviderAdapter,
  SsoTokenExchangeResult,
} from '../../src/modules/auth/sso/sso-provider.interface';

/**
 * Test-only adapter wrapper.
 *
 * WHY:
 * - Keeps E2E tests network-free without vi.mock() hoisting complexity.
 * - Still runs the *real* validateAndExtractIdentity logic.
 */
export class FakeSsoAdapter implements SsoProviderAdapter {
  readonly providerKey: 'google' | 'microsoft';

  private nextExchange: SsoTokenExchangeResult | Error | null = null;

  constructor(private readonly real: SsoProviderAdapter) {
    this.providerKey = real.providerKey;
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

  validateAndExtractIdentity(input: {
    idToken: string;
    expectedNonce: string;
    now: Date;
  }): SsoIdentityPayload {
    return this.real.validateAndExtractIdentity(input);
  }
}
