/**
 * frontend/src/shared/auth/redirects.ts
 *
 * WHY:
 * - Keeps route-state → pathname mapping in one place.
 * - Makes root/auth/dashboard placeholder gates consistent until richer UI lands.
 *
 * RULES:
 * - This file owns frontend route targets, not backend truth.
 * - Future route changes should update this file instead of scattering string literals.
 */

import type { AuthRouteState } from './route-state';

export const AUTH_PUBLIC_ENTRY_PATH = '/auth';
export const AUTH_TENANT_UNAVAILABLE_PATH = '/auth/unavailable';
export const AUTH_EMAIL_VERIFICATION_PATH = '/auth/continue/email-verification';
export const AUTH_MFA_SETUP_PATH = '/auth/continue/mfa-setup';
export const AUTH_MFA_VERIFY_PATH = '/auth/continue/mfa-verify';
export const AUTHENTICATED_APP_ENTRY_PATH = '/dashboard';
export const TOPOLOGY_CHECK_PATH = '/topology-check';

export function getRouteStateRedirectPath(state: AuthRouteState): string {
  switch (state.kind) {
    case 'TENANT_UNAVAILABLE':
      return AUTH_TENANT_UNAVAILABLE_PATH;
    case 'PUBLIC_ENTRY':
      return AUTH_PUBLIC_ENTRY_PATH;
    case 'EMAIL_VERIFICATION_REQUIRED':
      return AUTH_EMAIL_VERIFICATION_PATH;
    case 'MFA_SETUP_REQUIRED':
      return AUTH_MFA_SETUP_PATH;
    case 'MFA_REQUIRED':
      return AUTH_MFA_VERIFY_PATH;
    case 'AUTHENTICATED_APP':
      return AUTHENTICATED_APP_ENTRY_PATH;
    default: {
      const exhaustiveCheck: never = state;
      throw new Error(`Unhandled auth route state: ${String(exhaustiveCheck)}`);
    }
  }
}
