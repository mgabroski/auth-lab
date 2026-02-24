/**
 * backend/src/modules/auth/policies/register-next-action.policy.ts
 *
 * WHY:
 * - Pure decision: after registration + membership provisioning, decide nextAction.
 * - Mirrors login policy so flows stay consistent and future changes are localized.
 *
 * RULES (Decision 3 — Brick 11, LOCKED):
 * - If email is not verified → EMAIL_VERIFICATION_REQUIRED (always wins).
 * - Newly registered users via invite never have MFA configured yet.
 * - If MFA is required for the membership/tenant, nextAction is MFA_SETUP_REQUIRED.
 * - Otherwise nextAction is NONE.
 *
 * NOTE: For invite-based registration (Brick 7), emailVerified is always true
 * (DB default). This param only matters for public signup (Brick 11) where
 * emailVerified: false is explicitly set on new users.
 */

import type { MembershipRole } from '../../memberships/membership.types';
import type { AuthNextAction } from '../auth.types';

export type RegisterNextAction = Extract<
  AuthNextAction,
  'NONE' | 'MFA_SETUP_REQUIRED' | 'EMAIL_VERIFICATION_REQUIRED'
>;

export function decideRegisterNextAction(input: {
  role: MembershipRole;
  memberMfaRequired: boolean;
  /**
   * Decision 3 (Brick 11): when false, EMAIL_VERIFICATION_REQUIRED is returned
   * before any MFA check. Defaults to true — all invite-based callers omit this.
   */
  emailVerified?: boolean;
}): RegisterNextAction {
  // Decision 3: email verification always takes precedence over MFA.
  if (input.emailVerified === false) return 'EMAIL_VERIFICATION_REQUIRED';

  const mfaRequired = input.role === 'ADMIN' || input.memberMfaRequired;
  return mfaRequired ? 'MFA_SETUP_REQUIRED' : 'NONE';
}
