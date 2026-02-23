/**
 * backend/src/modules/auth/sso/sso-provider-registry.ts
 *
 * WHY:
 * - Single place to look up provider adapters by key.
 * - OCP: adding providers is register(new Adapter()) only.
 * - DIP: callers depend on the interface, not concretions.
 */

import { AppError } from '../../../shared/http/errors';
import type { SsoProviderAdapter } from './sso-provider.interface';

export class SsoProviderRegistry {
  private readonly adapters = new Map<string, SsoProviderAdapter>();

  register(adapter: SsoProviderAdapter): this {
    this.adapters.set(adapter.providerKey, adapter);
    return this;
  }

  getOrThrow(provider: string): SsoProviderAdapter {
    const adapter = this.adapters.get(provider);
    if (!adapter) {
      throw AppError.validationError('Invalid SSO provider', { provider });
    }
    return adapter;
  }

  has(provider: string): boolean {
    return this.adapters.has(provider);
  }
}
