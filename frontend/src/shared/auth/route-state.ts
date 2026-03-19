/**
 * frontend/src/shared/auth/route-state.ts
 *
 * WHY:
 * - Converts backend bootstrap truth into explicit frontend route categories.
 * - Keeps continuation/app-entry decisions centralized and easy to review.
 * - Splits fully-authenticated state by membership role so the root gate can hand off
 *   to the correct member or admin landing route.
 *
 * RULES:
 * - Route state must be derived from backend truth only (`/auth/config`, `/auth/me`).
 * - `nextAction` is authoritative.
 * - Do not infer auth continuation from scattered frontend heuristics.
 *
 * Note (Phase 9): workspace setup state (setupCompleted) lives in
 * ConfigResponse.tenant and is read directly by the admin dashboard page
 * to render a non-blocking banner. It does not produce a distinct route state —
 * all fully-authenticated admins resolve to AUTHENTICATED_ADMIN regardless of
 * whether setup is complete. See ADR 0003.
 */

import type { ConfigResponse, MeResponse } from './contracts';

export type PublicRouteState = {
  kind: 'PUBLIC_ENTRY';
  config: ConfigResponse;
  me: null;
};

export type TenantUnavailableRouteState = {
  kind: 'TENANT_UNAVAILABLE';
  config: ConfigResponse;
  me: null;
};

export type AuthenticatedMemberRouteState = {
  kind: 'AUTHENTICATED_MEMBER';
  config: ConfigResponse;
  me: MeResponse;
};

export type AuthenticatedAdminRouteState = {
  kind: 'AUTHENTICATED_ADMIN';
  config: ConfigResponse;
  me: MeResponse;
};

export type EmailVerificationRouteState = {
  kind: 'EMAIL_VERIFICATION_REQUIRED';
  config: ConfigResponse;
  me: MeResponse;
};

export type MfaSetupRouteState = {
  kind: 'MFA_SETUP_REQUIRED';
  config: ConfigResponse;
  me: MeResponse;
};

export type MfaVerifyRouteState = {
  kind: 'MFA_REQUIRED';
  config: ConfigResponse;
  me: MeResponse;
};

export type AuthRouteState =
  | PublicRouteState
  | TenantUnavailableRouteState
  | AuthenticatedMemberRouteState
  | AuthenticatedAdminRouteState
  | EmailVerificationRouteState
  | MfaSetupRouteState
  | MfaVerifyRouteState;

export function resolveAuthRouteState(input: {
  config: ConfigResponse;
  me: MeResponse | null;
}): AuthRouteState {
  const { config, me } = input;

  if (!config.tenant.isActive) {
    return {
      kind: 'TENANT_UNAVAILABLE',
      config,
      me: null,
    };
  }

  if (!me) {
    return {
      kind: 'PUBLIC_ENTRY',
      config,
      me: null,
    };
  }

  switch (me.nextAction) {
    case 'EMAIL_VERIFICATION_REQUIRED':
      return {
        kind: 'EMAIL_VERIFICATION_REQUIRED',
        config,
        me,
      };
    case 'MFA_SETUP_REQUIRED':
      return {
        kind: 'MFA_SETUP_REQUIRED',
        config,
        me,
      };
    case 'MFA_REQUIRED':
      return {
        kind: 'MFA_REQUIRED',
        config,
        me,
      };
    case 'NONE':
      return me.membership.role === 'ADMIN'
        ? {
            kind: 'AUTHENTICATED_ADMIN',
            config,
            me,
          }
        : {
            kind: 'AUTHENTICATED_MEMBER',
            config,
            me,
          };
    default: {
      const exhaustiveCheck: never = me.nextAction;
      throw new Error(`Unhandled auth nextAction: ${String(exhaustiveCheck)}`);
    }
  }
}
