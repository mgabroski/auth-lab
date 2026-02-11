/**
 * backend/src/modules/memberships/policies/membership-access.policy.ts
 *
 * WHY:
 * - Centralizes membership access rules.
 * - Pure logic (no DB / no I/O) => easy to unit test.
 *
 * RULES:
 * - Pure functions only.
 * - Throws module-level MembershipErrors.
 */

import type { Membership } from '../membership.types';
import { MembershipErrors } from '../membership.errors';

export function assertMembershipExists(
  membership: Membership | undefined,
): asserts membership is Membership {
  if (!membership) {
    throw MembershipErrors.membershipNotFound();
  }
}

/**
 * Asserts ACTIVE status. Blocks INVITED and SUSPENDED.
 * Use for login / authenticated access flows.
 */
export function assertMembershipIsActive(membership: Membership): void {
  if (membership.status === 'SUSPENDED') {
    throw MembershipErrors.membershipSuspended({ membershipId: membership.id });
  }
  if (membership.status === 'INVITED') {
    throw MembershipErrors.membershipStillInvited({ membershipId: membership.id });
  }
  if (membership.status !== 'ACTIVE') {
    throw MembershipErrors.membershipNotActive({ membershipId: membership.id });
  }
}

/**
 * Allows INVITED and ACTIVE; blocks only SUSPENDED.
 * Use for registration flow (where INVITED → ACTIVE is the goal).
 */
export function assertMembershipNotSuspended(membership: Membership): void {
  if (membership.status === 'SUSPENDED') {
    throw MembershipErrors.membershipSuspended({ membershipId: membership.id });
  }
}

/**
 * Asserts ADMIN role. Use for admin-only endpoints.
 */
export function assertMembershipRoleAdmin(membership: Membership): void {
  if (membership.role !== 'ADMIN') {
    throw MembershipErrors.membershipNotFound();
  }
}
