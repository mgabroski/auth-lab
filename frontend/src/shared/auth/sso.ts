/**
 * frontend/src/shared/auth/sso.ts
 *
 * WHY:
 * - SSO must start with a full browser navigation, not fetch().
 * - This helper centralizes the provider path + optional safe returnTo handling.
 * - Keeps future auth pages from duplicating OAuth start URL logic.
 */

import type { PublicSsoProvider } from './contracts';
import { isSafeReturnToPath } from './url-tokens';

export type StartSsoOptions = {
  returnTo?: string | null;
};

export function buildSsoStartPath(provider: PublicSsoProvider, options?: StartSsoOptions): string {
  const params = new URLSearchParams();

  if (isSafeReturnToPath(options?.returnTo)) {
    params.set('returnTo', options.returnTo);
  }

  const query = params.toString();
  return `/api/auth/sso/${provider}${query ? `?${query}` : ''}`;
}

export function startSso(provider: PublicSsoProvider, options?: StartSsoOptions): void {
  if (typeof window === 'undefined') {
    throw new Error('startSso() can only run in the browser.');
  }

  window.location.assign(buildSsoStartPath(provider, options));
}
