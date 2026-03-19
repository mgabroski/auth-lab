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
 *
 * PHASE 9 UPDATE (ADR 0003):
 * - Added ADMIN_SETTINGS_PATH = '/admin/settings'.
 * - `getPathForNextAction` now requires `role: MembershipRole`.
 *   NONE + ADMIN → /admin  |  NONE + MEMBER → /app  (fixes pre-existing role-blind routing).
 * - `getPostAuthRedirectPath` gains `role: MembershipRole` parameter and threads
 *   it through to `getPathForNextAction`.
 * - No FIRST_TIME_SETUP case — workspace setup state drives a UI banner on /admin,
 *   not an auth continuation redirect. See ADR 0003.
 */

import type { MembershipRole, AuthNextAction } from './contracts';
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
export const ADMIN_SETTINGS_PATH = '/admin/settings';
export const ADMIN_INVITES_PATH = '/admin/invites';
export const AUTHENTICATED_APP_ENTRY_PATH = AUTHENTICATED_MEMBER_ENTRY_PATH;
export const LEGACY_AUTHENTICATED_DASHBOARD_PATH = '/dashboard';
export const TOPOLOGY_CHECK_PATH = '/topology-check';

/**
 * Maps a backend `nextAction` + membership `role` to a frontend pathname.
 *
 * Phase 9: `role` is required. NONE resolves differently by role:
 *   NONE + ADMIN  → /admin
 *   NONE + MEMBER → /app
 *
 * Continuation states (EMAIL_VERIFICATION_REQUIRED, MFA_SETUP_REQUIRED,
 * MFA_REQUIRED) are role-independent.
 */
export function getPathForNextAction(nextAction: AuthNextAction, role: MembershipRole): string {
  switch (nextAction) {
    case 'NONE':
      return role === 'ADMIN' ? AUTHENTICATED_ADMIN_ENTRY_PATH : AUTHENTICATED_MEMBER_ENTRY_PATH;
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

function isContinuationReturnToPath(
  nextAction: AuthNextAction,
  role: MembershipRole,
  returnTo?: string | null,
): boolean {
  if (!isSafeReturnToPath(returnTo) || nextAction === 'NONE') {
    return false;
  }

  const expectedPath = getPathForNextAction(nextAction, role);
  return returnTo === expectedPath || returnTo.startsWith(`${expectedPath}?`);
}

/**
 * Resolves the final post-auth redirect path given a nextAction, role, and
 * optional returnTo hint from the URL.
 *
 * Rules:
 * - nextAction NONE + safe returnTo → returnTo
 * - nextAction is continuation + returnTo matches continuation path → returnTo
 * - otherwise → getPathForNextAction(nextAction, role)
 */
export function getPostAuthRedirectPath(
  nextAction: AuthNextAction,
  role: MembershipRole,
  returnTo?: string | null,
): string {
  if (nextAction === 'NONE' && isSafeReturnToPath(returnTo)) {
    return returnTo;
  }

  if (isSafeReturnToPath(returnTo) && isContinuationReturnToPath(nextAction, role, returnTo)) {
    return returnTo;
  }

  return getPathForNextAction(nextAction, role);
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
