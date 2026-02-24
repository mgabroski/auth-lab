/**
 * backend/src/modules/auth/policies/login-next-action.policy.ts
 *
 * WHY:
 * - Pure decision: after credential + membership checks, decide nextAction.
 * - Keeps orchestration (login flow) separate from policy (rules).
 *
 * RULES (Decision 3 — Brick 11, LOCKED):
 * - If email is not verified → EMAIL_VERIFICATION_REQUIRED (always wins).
 * - ADMIN always requires MFA.
 * - MEMBER requires MFA only if tenant.memberMfaRequired is true.
 * - If MFA is required but user has no verified secret → MFA_SETUP_REQUIRED.
 * - If MFA is required and user has verified secret → MFA_REQUIRED.
 * - If MFA not required → NONE.
 *
 * PRECEDENCE ORDER (locked):
 *   1. EMAIL_VERIFICATION_REQUIRED  (email not verified)
 *   2. MFA_SETUP_REQUIRED           (admin with no MFA secret)
 *   3. MFA_REQUIRED                 (admin/member with MFA secret, not yet verified this session)
 *   4. NONE                         (fully authenticated)
 *
 * Any deviation requires an ADR.
 */

import type { MembershipRole } from '../../memberships/membership.types';
import type { AuthNextAction } from '../auth.types';

export type LoginNextAction = AuthNextAction;

export function decideLoginNextAction(input: {
  role: MembershipRole;
  memberMfaRequired: boolean;
  hasVerifiedMfaSecret: boolean;
  /**
   * Decision 3 (Brick 11): when false, EMAIL_VERIFICATION_REQUIRED is returned
   * before any MFA check. Defaults to true to preserve existing behavior for
   * all callers that omit this param (invite registration, SSO).
   */
  emailVerified?: boolean;
}): LoginNextAction {
  // Decision 3: email verification always takes precedence over MFA.
  if (input.emailVerified === false) return 'EMAIL_VERIFICATION_REQUIRED';

  const mfaRequired = input.role === 'ADMIN' || input.memberMfaRequired;

  if (!mfaRequired) return 'NONE';

  // MFA required:
  // - if no verified secret exists → setup required
  // - if verified secret exists → verify required
  return input.hasVerifiedMfaSecret ? 'MFA_REQUIRED' : 'MFA_SETUP_REQUIRED';
}
