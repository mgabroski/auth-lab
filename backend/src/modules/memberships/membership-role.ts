/**
 * backend/src/modules/memberships/membership-role.ts
 *
 * WHY:
 * - Centralizes runtime membership-role parsing and legacy compatibility.
 * - Canonical runtime roles are ADMIN / AGENT / USER.
 * - MEMBER remains accepted only as a legacy alias for USER at controlled
 *   input/read boundaries during the compatibility window.
 *
 * RULES:
 * - Never silently promote an unknown value.
 * - MEMBER always normalizes to USER.
 * - Invalid values return null so callers can fail closed.
 */

export const CANONICAL_MEMBERSHIP_ROLES = ['ADMIN', 'AGENT', 'USER'] as const;
export type MembershipRole = (typeof CANONICAL_MEMBERSHIP_ROLES)[number];

export const LEGACY_MEMBER_ROLE = 'MEMBER' as const;
export type LegacyMembershipRole = typeof LEGACY_MEMBER_ROLE;

export type MembershipRoleInput = MembershipRole | LegacyMembershipRole;

export function parseMembershipRole(value: unknown): MembershipRole | null {
  switch (value) {
    case 'ADMIN':
      return 'ADMIN';
    case 'AGENT':
      return 'AGENT';
    case 'USER':
    case 'MEMBER':
      return 'USER';
    default:
      return null;
  }
}

export function normalizeMembershipRole(value: MembershipRoleInput): MembershipRole {
  return value === 'MEMBER' ? 'USER' : value;
}

export function requireMembershipRole(value: unknown): MembershipRole {
  const parsed = parseMembershipRole(value);
  if (!parsed) {
    throw new Error('Invalid membership role.');
  }
  return parsed;
}

export function isAdminMembershipRole(role: MembershipRole): boolean {
  return role === 'ADMIN';
}

export function isNonAdminMembershipRole(role: MembershipRole): boolean {
  return role === 'AGENT' || role === 'USER';
}
