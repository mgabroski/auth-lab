/**
 * frontend/src/shared/auth/redirects.ts
 *
 * WHY:
 * - Keeps route-state → pathname mapping in one place.
 * - Makes root/auth/protected/public-entry flows consistent.
 * - Centralizes post-auth redirects driven by backend `nextAction` truth.
 *
 * RULES:
 * - This file owns frontend route targets, not backend truth.
 * - Future route changes should update this file instead of scattering string literals.
 */

import type { AuthNextAction } from './contracts';
import type { AuthRouteState } from './route-state';
import { isSafeReturnToPath } from './url-tokens';

export const ROOT_HANDOFF_PATH = '/';
export const AUTH_PUBLIC_ENTRY_PATH = '/auth/login';
export const AUTH_LOGIN_PATH = '/auth/login';
export const AUTH_REGISTER_PATH = '/auth/register';
export const AUTH_SIGNUP_PATH = '/auth/signup';
export const AUTH_FORGOT_PASSWORD_PATH = '/auth/forgot-password';
export const AUTH_RESET_PASSWORD_PATH = '/auth/reset-password';
export const AUTH_TENANT_UNAVAILABLE_PATH = '/auth/unavailable';
export const AUTH_ACCEPT_INVITE_PATH = '/accept-invite';
export const AUTH_EMAIL_VERIFICATION_PATH = '/verify-email';
export const AUTH_MFA_SETUP_PATH = '/auth/mfa/setup';
export const AUTH_MFA_VERIFY_PATH = '/auth/mfa/verify';
export const AUTH_SSO_DONE_PATH = '/auth/sso/done';
export const AUTHENTICATED_MEMBER_ENTRY_PATH = '/app';
export const AUTHENTICATED_ADMIN_ENTRY_PATH = '/admin';
export const ADMIN_INVITES_PATH = '/admin/invites';
export const AUTHENTICATED_APP_ENTRY_PATH = AUTHENTICATED_MEMBER_ENTRY_PATH;
export const LEGACY_AUTHENTICATED_DASHBOARD_PATH = '/dashboard';
export const TOPOLOGY_CHECK_PATH = '/topology-check';

export function getPathForNextAction(nextAction: AuthNextAction): string {
  switch (nextAction) {
    case 'NONE':
      return AUTHENTICATED_APP_ENTRY_PATH;
    case 'EMAIL_VERIFICATION_REQUIRED':
      return AUTH_EMAIL_VERIFICATION_PATH;
    case 'MFA_SETUP_REQUIRED':
      return AUTH_MFA_SETUP_PATH;
    case 'MFA_REQUIRED':
      return AUTH_MFA_VERIFY_PATH;
    default: {
      const exhaustiveCheck: never = nextAction;
      throw new Error(`Unhandled auth nextAction: ${String(exhaustiveCheck)}`);
    }
  }
}

function isContinuationReturnToPath(nextAction: AuthNextAction, returnTo?: string | null): boolean {
  if (!isSafeReturnToPath(returnTo) || nextAction === 'NONE') {
    return false;
  }

  const expectedPath = getPathForNextAction(nextAction);
  return returnTo === expectedPath || returnTo.startsWith(`${expectedPath}?`);
}

export function getPostAuthRedirectPath(
  nextAction: AuthNextAction,
  returnTo?: string | null,
): string {
  if (nextAction === 'NONE' && isSafeReturnToPath(returnTo)) {
    return returnTo;
  }

  if (isSafeReturnToPath(returnTo) && isContinuationReturnToPath(nextAction, returnTo)) {
    return returnTo;
  }

  return getPathForNextAction(nextAction);
}

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
    case 'AUTHENTICATED_MEMBER':
      return AUTHENTICATED_MEMBER_ENTRY_PATH;
    case 'AUTHENTICATED_ADMIN':
      return AUTHENTICATED_ADMIN_ENTRY_PATH;
    default: {
      const exhaustiveCheck: never = state;
      throw new Error(`Unhandled auth route state: ${String(exhaustiveCheck)}`);
    }
  }
}
