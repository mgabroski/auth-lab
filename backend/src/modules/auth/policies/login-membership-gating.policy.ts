/**
 * backend/src/modules/auth/policies/login-membership-gating.policy.ts
 *
 * WHY:
 * - Login membership gating is a business/security rule.
 * - Keep it pure + unit-testable (no DB, no HTTP).
 *
 * RULES:
 * - If membership is missing → no access.
 * - If membership is SUSPENDED → suspended.
 * - If membership is INVITED → invite not yet accepted.
 * - Otherwise OK.
 *
 * IMPORTANT:
 * - The auth.login flow needs reason codes for the two-phase audit context.
 * - This function throws the correct error and carries the reason code so the
 *   service can set failureCtx before throwing.
 */

import { AuthErrors } from '../auth.errors';

export type MembershipStatus = 'ACTIVE' | 'INVITED' | 'SUSPENDED';

export type MembershipLike = Readonly<{
  id: string;
  status: MembershipStatus;
  role: 'ADMIN' | 'MEMBER';
}>;

export type LoginMembershipGatingFailure =
  | { reason: 'no_membership'; error: Error }
  | { reason: 'suspended'; error: Error }
  | { reason: 'invite_not_accepted'; error: Error };

/**
 * Returns null when OK; otherwise returns failure payload (reason + error).
 * This keeps the service in control of building failureCtx before throwing.
 */
export function getLoginMembershipGatingFailure(
  membership: MembershipLike | undefined,
): LoginMembershipGatingFailure | null {
  if (!membership) {
    return { reason: 'no_membership', error: AuthErrors.noAccess() };
  }
  if (membership.status === 'SUSPENDED') {
    return { reason: 'suspended', error: AuthErrors.accountSuspended() };
  }
  if (membership.status === 'INVITED') {
    return { reason: 'invite_not_accepted', error: AuthErrors.inviteNotYetAccepted() };
  }
  return null;
}

/**
 * Asserts membership is valid for login and narrows type for the rest of the flow.
 */
export function assertLoginMembershipAllowed(
  membership: MembershipLike | undefined,
): asserts membership is MembershipLike {
  const failure = getLoginMembershipGatingFailure(membership);
  if (failure) throw failure.error;
}
