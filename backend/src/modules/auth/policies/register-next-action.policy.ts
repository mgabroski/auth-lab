/**
 * backend/src/modules/auth/policies/register-next-action.policy.ts
 *
 * WHY:
 * - Pure decision: after registration + membership provisioning, decide nextAction.
 * - Mirrors login policy so flows stay consistent and future changes are localized.
 *
 * RULES (current behavior):
 * - Newly registered users never have MFA configured yet.
 * - If MFA is required for the membership/tenant, nextAction is MFA_SETUP_REQUIRED.
 * - Otherwise nextAction is NONE.
 */

import type { MembershipRole } from '../../memberships/membership.types';

export type RegisterNextAction = 'NONE' | 'MFA_SETUP_REQUIRED';

export function decideRegisterNextAction(input: {
  role: MembershipRole;
  memberMfaRequired: boolean;
}): RegisterNextAction {
  const mfaRequired = input.role === 'ADMIN' || input.memberMfaRequired;
  return mfaRequired ? 'MFA_SETUP_REQUIRED' : 'NONE';
}
