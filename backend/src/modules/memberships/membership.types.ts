/**
 * backend/src/modules/memberships/membership.types.ts
 *
 * WHY:
 * - A Membership connects a User to a Tenant.
 * - Defines role (ADMIN/MEMBER) and status (INVITED/ACTIVE/SUSPENDED).
 * - Access is decided by membership, never by user alone.
 *
 * RULES:
 * - Keep aligned with DB schema.
 * - Avoid leaking DB naming (snake_case) outside DAL/queries.
 */

export type MembershipId = string;

export type MembershipRole = 'ADMIN' | 'MEMBER';

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
