/**
 * backend/src/modules/auth/policies/mfa-required.policy.ts
 *
 * WHY:
 * - MFA requirement is a business/security rule.
 * - Keep it pure + unit-testable (no DB, no HTTP, no clocks).
 *
 * RULE:
 * - Admins ALWAYS require MFA.
 * - Agent and User follow the existing non-admin tenant member MFA policy.
 */

import type { MembershipRole } from '../../memberships/membership.types';

export function isMfaRequiredForLogin(input: {
  role: MembershipRole;
  tenantMemberMfaRequired: boolean;
}): boolean {
  return input.role === 'ADMIN' || input.tenantMemberMfaRequired;
}
