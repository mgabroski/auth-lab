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
export type { Membership, MembershipRole, MembershipStatus } from './membership.types';
