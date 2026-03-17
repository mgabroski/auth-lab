/**
 * backend/src/modules/_shared/policies/tenant-entry-auth-policy.ts
 *
 * WHY:
 * - Phase 1A.5 needs one isolated, reviewable decision unit for tenant-entry /
 *   auth-entry policy semantics.
 * - Runtime flows must not re-derive these entry decisions ad hoc in multiple
 *   places. This file encodes the decision matrix only; it does not orchestrate
 *   DB, HTTP, sessions, redirects, or provider callbacks.
 *
 * RULES:
 * - Pure only: no DB, no HTTP, no side effects.
 * - Encodes entry semantics, not runtime enforcement wiring.
 * - Keeps expired invited state explicit as a blocked entry.
 * - LOCK-4: expired invites never activate through SSO.
 * - Defines allowed / forbidden nextAction families by entry path so later
 *   phases can wire decisions without duplicating the matrix.
 *
 * PHASE 1A.5 SCOPE:
 * - public-signup-allowed entry
 * - public-signup-blocked entry
 * - invite-required entry
 * - valid invited entry
 * - expired invited entry
 * - existing ACTIVE membership
 * - existing SUSPENDED membership
 * - pending invited activation after one-time invite consumption
 */

import type { AuthNextAction } from '../../auth/auth.types';
import type { TenantEntryPolicyInput } from './tenant-entry-policy-input';

export type AuthEntryPath = 'PUBLIC_SIGNUP' | 'INVITED_ENTRY' | 'EXISTING_MEMBER_AUTH' | 'BLOCKED';

export type AuthEntryDecisionCode =
  | 'PUBLIC_SIGNUP_ALLOWED'
  | 'PUBLIC_SIGNUP_BLOCKED'
  | 'INVITE_REQUIRED'
  | 'INVITED_VALID'
  | 'INVITED_EXPIRED'
  | 'INVITED_PENDING_ACTIVATION'
  | 'ACTIVE_MEMBERSHIP'
  | 'SUSPENDED_MEMBERSHIP';

export const ALL_AUTH_ENTRY_NEXT_ACTIONS = [
  'NONE',
  'EMAIL_VERIFICATION_REQUIRED',
  'MFA_SETUP_REQUIRED',
  'MFA_REQUIRED',
] as const satisfies readonly AuthNextAction[];

export const PUBLIC_SIGNUP_NEXT_ACTIONS = [
  'NONE',
  'EMAIL_VERIFICATION_REQUIRED',
] as const satisfies readonly AuthNextAction[];

export const INVITED_ENTRY_NEXT_ACTIONS = [
  'NONE',
  'MFA_SETUP_REQUIRED',
  'MFA_REQUIRED',
] as const satisfies readonly AuthNextAction[];

export const EXISTING_MEMBER_AUTH_NEXT_ACTIONS = [
  'NONE',
  'EMAIL_VERIFICATION_REQUIRED',
  'MFA_SETUP_REQUIRED',
  'MFA_REQUIRED',
] as const satisfies readonly AuthNextAction[];

export const ALLOWED_NEXT_ACTIONS_BY_ENTRY_PATH = {
  PUBLIC_SIGNUP: PUBLIC_SIGNUP_NEXT_ACTIONS,
  INVITED_ENTRY: INVITED_ENTRY_NEXT_ACTIONS,
  EXISTING_MEMBER_AUTH: EXISTING_MEMBER_AUTH_NEXT_ACTIONS,
  BLOCKED: [] as const,
} satisfies Record<AuthEntryPath, readonly AuthNextAction[]>;

export type AuthEntryPolicyDecision = {
  code: AuthEntryDecisionCode;
  entryPath: AuthEntryPath;
  isEntryAllowed: boolean;
  allowedNextActions: AuthNextAction[];
  forbiddenNextActions: AuthNextAction[];
};

function buildDecision(params: {
  code: AuthEntryDecisionCode;
  entryPath: AuthEntryPath;
}): AuthEntryPolicyDecision {
  const allowedNextActions = [...ALLOWED_NEXT_ACTIONS_BY_ENTRY_PATH[params.entryPath]];
  const forbiddenNextActions = ALL_AUTH_ENTRY_NEXT_ACTIONS.filter(
    (nextAction) => !allowedNextActions.includes(nextAction),
  );

  return {
    code: params.code,
    entryPath: params.entryPath,
    isEntryAllowed: params.entryPath !== 'BLOCKED',
    allowedNextActions,
    forbiddenNextActions,
  };
}

/**
 * Decide the high-level auth-entry policy classification from normalized
 * tenant/invite/membership state.
 *
 * IMPORTANT:
 * - This is intentionally broader than any single runtime flow.
 * - It returns the entry-path family and the allowed nextAction family for that
 *   path, but it does not choose the concrete nextAction for a specific user.
 * - Concrete nextAction selection still belongs to later provider-/flow-specific
 *   policies and orchestration.
 */
export function decideTenantEntryAuthPolicy(
  input: TenantEntryPolicyInput,
): AuthEntryPolicyDecision {
  if (input.membership.state === 'SUSPENDED') {
    return buildDecision({
      code: 'SUSPENDED_MEMBERSHIP',
      entryPath: 'BLOCKED',
    });
  }

  if (input.membership.state === 'ACTIVE') {
    return buildDecision({
      code: 'ACTIVE_MEMBERSHIP',
      entryPath: 'EXISTING_MEMBER_AUTH',
    });
  }

  if (input.invite.state === 'EXPIRED') {
    return buildDecision({
      code: 'INVITED_EXPIRED',
      entryPath: 'BLOCKED',
    });
  }

  if (input.membership.state === 'INVITED' || input.invite.state === 'VALID') {
    return buildDecision({
      code: 'INVITED_VALID',
      entryPath: 'INVITED_ENTRY',
    });
  }

  if (input.invite.state === 'ONE_TIME_USED' || input.entry.activationState === 'PENDING') {
    return buildDecision({
      code: 'INVITED_PENDING_ACTIVATION',
      entryPath: 'INVITED_ENTRY',
    });
  }

  if (input.tenant.adminInviteRequired) {
    return buildDecision({
      code: 'INVITE_REQUIRED',
      entryPath: 'BLOCKED',
    });
  }

  if (input.tenant.publicSignupEnabled) {
    return buildDecision({
      code: 'PUBLIC_SIGNUP_ALLOWED',
      entryPath: 'PUBLIC_SIGNUP',
    });
  }

  return buildDecision({
    code: 'PUBLIC_SIGNUP_BLOCKED',
    entryPath: 'BLOCKED',
  });
}

export function isNextActionAllowedForDecision(
  decision: AuthEntryPolicyDecision,
  nextAction: AuthNextAction,
): boolean {
  return decision.allowedNextActions.includes(nextAction);
}
