/**
 * backend/src/modules/memberships/membership.types.ts
 *
 * WHY:
 * - A Membership connects a User to a Tenant.
 * - Defines canonical runtime role (ADMIN/AGENT/USER) and status
 *   (INVITED/ACTIVE/SUSPENDED).
 * - Access is decided by membership, never by user alone.
 *
 * RULES:
 * - Keep aligned with DB schema.
 * - MEMBER is accepted only as a legacy input/read alias through
 *   membership-role.ts and normalizes to USER.
 * - Avoid leaking DB naming (snake_case) outside DAL/queries.
 */

import type { MembershipRole } from './membership-role';

export type { MembershipRole, MembershipRoleInput, LegacyMembershipRole } from './membership-role';

export type MembershipId = string;

export type MembershipStatus = 'INVITED' | 'ACTIVE' | 'SUSPENDED';

export type Membership = {
  id: MembershipId;
  tenantId: string;
  userId: string;

  role: MembershipRole;
  status: MembershipStatus;

  invitedAt: Date;
  acceptedAt: Date | null;
  suspendedAt: Date | null;

  createdAt: Date;
  updatedAt: Date;
};
