/**
 * frontend/src/shared/auth/route-state.ts
 *
 * WHY:
 * - Converts backend bootstrap truth into explicit frontend route categories.
 * - Keeps continuation/app-entry decisions centralized and easy to review.
 *
 * RULES:
 * - Route state must be derived from backend truth only (`/auth/config`, `/auth/me`).
 * - `nextAction` is authoritative.
 * - Do not infer auth continuation from scattered frontend heuristics.
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

export type AuthenticatedAppRouteState = {
  kind: 'AUTHENTICATED_APP';
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
  | AuthenticatedAppRouteState
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
      return {
        kind: 'AUTHENTICATED_APP',
        config,
        me,
      };
    default: {
      const exhaustiveCheck: never = me.nextAction;
      throw new Error(`Unhandled auth nextAction: ${String(exhaustiveCheck)}`);
    }
  }
}
