/**
 * backend/src/modules/auth/policies/mfa-required.policy.ts
 *
 * WHY:
 * - MFA requirement is a business/security rule.
 * - Keep it pure + unit-testable (no DB, no HTTP, no clocks).
 *
 * RULE:
 * - Admins ALWAYS require MFA.
 * - Members require MFA only when tenant setting enforces it.
 */

export type MembershipRole = 'ADMIN' | 'MEMBER';

export function isMfaRequiredForLogin(input: {
  role: MembershipRole;
  tenantMemberMfaRequired: boolean;
}): boolean {
  return input.role === 'ADMIN' || input.tenantMemberMfaRequired;
}
