/**
 * backend/src/modules/auth/policies/login-next-action.policy.ts
 *
 * WHY:
 * - Pure decision: after credential + membership checks, decide nextAction.
 * - Keeps orchestration (login flow) separate from policy (rules).
 *
 * RULES:
 * - ADMIN always requires MFA.
 * - MEMBER requires MFA only if tenant.memberMfaRequired is true.
 * - If MFA is required but user has no verified secret => must set up MFA.
 * - If MFA is required and user has verified secret => must verify MFA for session.
 * - If MFA not required => authenticated.
 */

import type { MembershipRole } from '../../memberships/membership.types';

export type LoginNextAction = 'NONE' | 'MFA_REQUIRED' | 'MFA_SETUP_REQUIRED';

export function decideLoginNextAction(input: {
  role: MembershipRole;
  memberMfaRequired: boolean;
  hasVerifiedMfaSecret: boolean;
}): LoginNextAction {
  const mfaRequired = input.role === 'ADMIN' || input.memberMfaRequired;

  if (!mfaRequired) return 'NONE';

  // MFA required:
  // - if no verified secret exists => setup required
  // - if verified secret exists => verify required
  return input.hasVerifiedMfaSecret ? 'MFA_REQUIRED' : 'MFA_SETUP_REQUIRED';
}
