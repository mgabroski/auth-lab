/**
 * backend/src/modules/memberships/index.ts
 *
 * WHY:
 * - Define the public surface of the memberships module.
 * - Prevent cross-module coupling via deep imports into /queries or /dal.
 *
 * RULES:
 * - Only export stable, read-only contracts needed by other modules.
 * - Keep exports minimal; add more only when explicitly required.
 */

export { getMembershipByTenantAndUser } from './queries/membership.queries';
export {
  CANONICAL_MEMBERSHIP_ROLES,
  LEGACY_MEMBER_ROLE,
  isAdminMembershipRole,
  isNonAdminMembershipRole,
  normalizeMembershipRole,
  parseMembershipRole,
  requireMembershipRole,
} from './membership-role';
export type {
  LegacyMembershipRole,
  Membership,
  MembershipRole,
  MembershipRoleInput,
  MembershipStatus,
} from './membership.types';

export type { MembershipRepo } from './dal/membership.repo';
