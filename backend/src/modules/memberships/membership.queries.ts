/**
 * backend/src/modules/memberships/membership.queries.ts
 *
 * WHY:
 * - Queries are read-only and side-effect free.
 * - They shape DB rows into Membership domain types.
 * - Always tenant-scoped.
 *
 * RULES:
 * - Read-only.
 * - No AppError.
 */

import type { DbExecutor } from '../../shared/db/db';
import {
  selectMembershipByTenantAndUserSql,
  selectMembershipByIdSql,
} from './dal/membership.query-sql';
import type { MembershipRow } from './dal/membership.query-sql';
import type { Membership, MembershipRole, MembershipStatus } from './membership.types';

function parseMembershipRole(value: string): MembershipRole {
  if (value === 'ADMIN' || value === 'MEMBER') return value;
  return 'MEMBER';
}

function parseMembershipStatus(value: string): MembershipStatus {
  if (value === 'INVITED' || value === 'ACTIVE' || value === 'SUSPENDED') return value;
  return 'SUSPENDED';
}

function toMembership(row: MembershipRow): Membership {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    userId: row.user_id,
    role: parseMembershipRole(row.role),
    status: parseMembershipStatus(row.status),
    invitedAt: row.invited_at,
    acceptedAt: row.accepted_at ?? null,
    suspendedAt: row.suspended_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function getMembershipByTenantAndUser(
  db: DbExecutor,
  params: { tenantId: string; userId: string },
): Promise<Membership | undefined> {
  const row = await selectMembershipByTenantAndUserSql(db, params);
  if (!row) return undefined;
  return toMembership(row);
}

export async function getMembershipById(
  db: DbExecutor,
  membershipId: string,
): Promise<Membership | undefined> {
  const row = await selectMembershipByIdSql(db, membershipId);
  if (!row) return undefined;
  return toMembership(row);
}
