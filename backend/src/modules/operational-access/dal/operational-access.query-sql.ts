/**
 * backend/src/modules/operational-access/dal/operational-access.query-sql.ts
 *
 * WHY:
 * - Raw Kysely queries for Operational Access configuration and the first
 *   backend resolver proof surface.
 * - Keeps tenant scoping and fail-closed reads at the query boundary.
 *
 * RULES:
 * - No AppError.
 * - No frontend or tenant-created permission strings.
 * - No business decisions beyond tenant-scoped filtering and active-target pruning.
 */

import { sql } from 'kysely';
import type { DbExecutor } from '../../../shared/db/db';
import type {
  OperationalAccessActionKey,
  OperationalAccessPrimaryWhereKey,
  OperationalAccessWhichRecordsKey,
} from '../operational-access.types';

export type OperationalAccessTenantCapabilityRow = {
  operational_access_enabled: boolean;
};

export type OperationalAccessGroupRow = {
  id: string;
  name: string;
  description: string | null;
  level: string;
  status: string;
  member_count: string | number | bigint;
  grant_count: string | number | bigint;
  responsible_for_assignment_count: string | number | bigint;
};

export type OperationalAccessStoredGroupRow = {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  level: string;
  status: string;
};

export type OperationalAccessGrantRow = {
  id: string;
  tenant_id: string;
  group_id: string;
  action_key: string;
  primary_where: string;
  which_records_key: string;
  created_at: Date;
  updated_at: Date;
};

export type OperationalAccessMembershipRow = {
  membership_id: string;
  user_id: string;
  email: string;
  name: string | null;
  role: string;
  status: string;
};

export type OperationalAccessResponsibleForRow = {
  agent_membership_id: string;
  agent_user_id: string;
  agent_email: string;
  agent_name: string | null;
  target_membership_id: string;
  target_user_id: string;
  target_email: string;
  target_name: string | null;
  created_at: Date;
};

export type OperationalAccessResolverGrantRow = {
  group_id: string;
  action_key: string;
  primary_where: string;
  which_records_key: string;
};

export type OperationalAccessRuntimePersonRow = {
  membership_id: string;
  user_id: string;
  email: string;
  name: string | null;
  role: string;
  status: string;
};

export type OperationalAccessOversightRow = {
  overseer_membership_id: string;
  target_membership_id: string;
  includes_responsible_people: boolean;
  reason: string;
  review_at: Date;
};

export type OperationalAccessTemporaryCoverageRow = {
  id: string;
  covering_membership_id: string;
  covered_membership_id: string;
  starts_at: Date;
  expires_at: Date;
  reason: string;
  review_at: Date | null;
};

export type OperationalAccessSpecialAccessRow = {
  id: string;
  membership_id: string;
  target_membership_id: string;
  action_key: string;
  reason: string;
  review_at: Date;
  expires_at: Date;
};

const STORED_GROUP_COLUMNS = ['id', 'tenant_id', 'name', 'description', 'level', 'status'] as const;

const GRANT_COLUMNS = [
  'id',
  'tenant_id',
  'group_id',
  'action_key',
  'primary_where',
  'which_records_key',
  'created_at',
  'updated_at',
] as const;

export async function selectOperationalAccessTenantCapabilitySql(
  db: DbExecutor,
  tenantId: string,
): Promise<OperationalAccessTenantCapabilityRow | undefined> {
  return db
    .selectFrom('tenants')
    .select(['operational_access_enabled'])
    .where('id', '=', tenantId)
    .executeTakeFirst();
}

export async function selectActiveAgentGroupsSql(
  db: DbExecutor,
  tenantId: string,
): Promise<OperationalAccessGroupRow[]> {
  return db
    .selectFrom('tenant_groups')
    .leftJoin('tenant_group_members', (join) =>
      join
        .onRef('tenant_group_members.group_id', '=', 'tenant_groups.id')
        .onRef('tenant_group_members.tenant_id', '=', 'tenant_groups.tenant_id'),
    )
    .leftJoin('tenant_oa_group_grants', (join) =>
      join
        .onRef('tenant_oa_group_grants.group_id', '=', 'tenant_groups.id')
        .onRef('tenant_oa_group_grants.tenant_id', '=', 'tenant_groups.tenant_id'),
    )
    .leftJoin('tenant_oa_responsible_for', (join) =>
      join
        .onRef('tenant_oa_responsible_for.group_id', '=', 'tenant_groups.id')
        .onRef('tenant_oa_responsible_for.tenant_id', '=', 'tenant_groups.tenant_id'),
    )
    .select((eb) => [
      'tenant_groups.id as id',
      'tenant_groups.name as name',
      'tenant_groups.description as description',
      'tenant_groups.level as level',
      'tenant_groups.status as status',
      eb.fn.count<string>('tenant_group_members.membership_id').distinct().as('member_count'),
      eb.fn.count<string>('tenant_oa_group_grants.id').distinct().as('grant_count'),
      eb.fn
        .count<string>('tenant_oa_responsible_for.target_membership_id')
        .distinct()
        .as('responsible_for_assignment_count'),
    ])
    .where('tenant_groups.tenant_id', '=', tenantId)
    .where('tenant_groups.status', '=', 'ACTIVE')
    .where('tenant_groups.level', '=', 'AGENT')
    .groupBy([
      'tenant_groups.id',
      'tenant_groups.name',
      'tenant_groups.description',
      'tenant_groups.level',
      'tenant_groups.status',
    ])
    .orderBy('tenant_groups.normalized_name', 'asc')
    .execute() as Promise<OperationalAccessGroupRow[]>;
}

export async function selectOperationalAccessGroupSql(
  db: DbExecutor,
  input: { tenantId: string; groupId: string },
): Promise<OperationalAccessGroupRow | undefined> {
  return db
    .selectFrom('tenant_groups')
    .leftJoin('tenant_group_members', (join) =>
      join
        .onRef('tenant_group_members.group_id', '=', 'tenant_groups.id')
        .onRef('tenant_group_members.tenant_id', '=', 'tenant_groups.tenant_id'),
    )
    .leftJoin('tenant_oa_group_grants', (join) =>
      join
        .onRef('tenant_oa_group_grants.group_id', '=', 'tenant_groups.id')
        .onRef('tenant_oa_group_grants.tenant_id', '=', 'tenant_groups.tenant_id'),
    )
    .leftJoin('tenant_oa_responsible_for', (join) =>
      join
        .onRef('tenant_oa_responsible_for.group_id', '=', 'tenant_groups.id')
        .onRef('tenant_oa_responsible_for.tenant_id', '=', 'tenant_groups.tenant_id'),
    )
    .select((eb) => [
      'tenant_groups.id as id',
      'tenant_groups.name as name',
      'tenant_groups.description as description',
      'tenant_groups.level as level',
      'tenant_groups.status as status',
      eb.fn.count<string>('tenant_group_members.membership_id').distinct().as('member_count'),
      eb.fn.count<string>('tenant_oa_group_grants.id').distinct().as('grant_count'),
      eb.fn
        .count<string>('tenant_oa_responsible_for.target_membership_id')
        .distinct()
        .as('responsible_for_assignment_count'),
    ])
    .where('tenant_groups.tenant_id', '=', input.tenantId)
    .where('tenant_groups.id', '=', input.groupId)
    .groupBy([
      'tenant_groups.id',
      'tenant_groups.name',
      'tenant_groups.description',
      'tenant_groups.level',
      'tenant_groups.status',
    ])
    .executeTakeFirst() as Promise<OperationalAccessGroupRow | undefined>;
}

export async function selectStoredOperationalAccessGroupSql(
  db: DbExecutor,
  input: { tenantId: string; groupId: string },
): Promise<OperationalAccessStoredGroupRow | undefined> {
  return db
    .selectFrom('tenant_groups')
    .select(STORED_GROUP_COLUMNS)
    .where('tenant_id', '=', input.tenantId)
    .where('id', '=', input.groupId)
    .executeTakeFirst() as Promise<OperationalAccessStoredGroupRow | undefined>;
}

export async function selectGroupGrantsSql(
  db: DbExecutor,
  input: { tenantId: string; groupId: string },
): Promise<OperationalAccessGrantRow[]> {
  return db
    .selectFrom('tenant_oa_group_grants')
    .select(GRANT_COLUMNS)
    .where('tenant_id', '=', input.tenantId)
    .where('group_id', '=', input.groupId)
    .orderBy('action_key', 'asc')
    .execute() as Promise<OperationalAccessGrantRow[]>;
}

export async function replaceGroupGrantsSql(
  db: DbExecutor,
  input: {
    tenantId: string;
    groupId: string;
    actorMembershipId: string;
    grants: Array<{
      actionKey: OperationalAccessActionKey;
      primaryWhere: OperationalAccessPrimaryWhereKey;
      whichRecordsKey: OperationalAccessWhichRecordsKey;
    }>;
  },
): Promise<void> {
  await db
    .deleteFrom('tenant_oa_group_grants')
    .where('tenant_id', '=', input.tenantId)
    .where('group_id', '=', input.groupId)
    .execute();

  if (input.grants.length === 0) return;

  await db
    .insertInto('tenant_oa_group_grants')
    .values(
      input.grants.map((grant) => ({
        tenant_id: input.tenantId,
        group_id: input.groupId,
        action_key: grant.actionKey,
        primary_where: grant.primaryWhere,
        which_records_key: grant.whichRecordsKey,
        created_by_membership_id: input.actorMembershipId,
        updated_by_membership_id: input.actorMembershipId,
      })),
    )
    .execute();
}

export async function selectActiveMembershipSql(
  db: DbExecutor,
  input: { tenantId: string; membershipId: string },
): Promise<OperationalAccessMembershipRow | undefined> {
  return db
    .selectFrom('memberships')
    .innerJoin('users', 'users.id', 'memberships.user_id')
    .select([
      'memberships.id as membership_id',
      'users.id as user_id',
      'users.email as email',
      'users.name as name',
      'memberships.role as role',
      'memberships.status as status',
    ])
    .where('memberships.tenant_id', '=', input.tenantId)
    .where('memberships.id', '=', input.membershipId)
    .where('memberships.status', '=', 'ACTIVE')
    .executeTakeFirst() as Promise<OperationalAccessMembershipRow | undefined>;
}

export async function selectActivePeopleSql(
  db: DbExecutor,
  tenantId: string,
): Promise<OperationalAccessMembershipRow[]> {
  return db
    .selectFrom('memberships')
    .innerJoin('users', 'users.id', 'memberships.user_id')
    .select([
      'memberships.id as membership_id',
      'users.id as user_id',
      'users.email as email',
      'users.name as name',
      'memberships.role as role',
      'memberships.status as status',
    ])
    .where('memberships.tenant_id', '=', tenantId)
    .where('memberships.status', '=', 'ACTIVE')
    .orderBy('users.email', 'asc')
    .execute() as Promise<OperationalAccessMembershipRow[]>;
}

export async function selectActiveGroupMemberSql(
  db: DbExecutor,
  input: { tenantId: string; groupId: string; membershipId: string },
): Promise<{ membership_id: string } | undefined> {
  return db
    .selectFrom('tenant_group_members')
    .select(['membership_id'])
    .where('tenant_id', '=', input.tenantId)
    .where('group_id', '=', input.groupId)
    .where('membership_id', '=', input.membershipId)
    .executeTakeFirst();
}

export async function selectResponsibleForAssignmentsSql(
  db: DbExecutor,
  input: { tenantId: string; groupId: string },
): Promise<OperationalAccessResponsibleForRow[]> {
  return db
    .selectFrom('tenant_oa_responsible_for')
    .innerJoin('memberships as agent_membership', (join) =>
      join
        .onRef('agent_membership.id', '=', 'tenant_oa_responsible_for.agent_membership_id')
        .onRef('agent_membership.tenant_id', '=', 'tenant_oa_responsible_for.tenant_id'),
    )
    .innerJoin('users as agent_user', 'agent_user.id', 'agent_membership.user_id')
    .innerJoin('memberships as target_membership', (join) =>
      join
        .onRef('target_membership.id', '=', 'tenant_oa_responsible_for.target_membership_id')
        .onRef('target_membership.tenant_id', '=', 'tenant_oa_responsible_for.tenant_id'),
    )
    .innerJoin('users as target_user', 'target_user.id', 'target_membership.user_id')
    .select([
      'tenant_oa_responsible_for.agent_membership_id as agent_membership_id',
      'agent_user.id as agent_user_id',
      'agent_user.email as agent_email',
      'agent_user.name as agent_name',
      'tenant_oa_responsible_for.target_membership_id as target_membership_id',
      'target_user.id as target_user_id',
      'target_user.email as target_email',
      'target_user.name as target_name',
      'tenant_oa_responsible_for.created_at as created_at',
    ])
    .where('tenant_oa_responsible_for.tenant_id', '=', input.tenantId)
    .where('tenant_oa_responsible_for.group_id', '=', input.groupId)
    .where('agent_membership.status', '=', 'ACTIVE')
    .where('target_membership.status', '=', 'ACTIVE')
    .orderBy('agent_user.email', 'asc')
    .orderBy('target_user.email', 'asc')
    .execute() as Promise<OperationalAccessResponsibleForRow[]>;
}

export async function replaceResponsibleForAssignmentsSql(
  db: DbExecutor,
  input: {
    tenantId: string;
    groupId: string;
    actorMembershipId: string;
    assignments: Array<{ agentMembershipId: string; targetMembershipId: string }>;
  },
): Promise<void> {
  await db
    .deleteFrom('tenant_oa_responsible_for')
    .where('tenant_id', '=', input.tenantId)
    .where('group_id', '=', input.groupId)
    .execute();

  if (input.assignments.length === 0) return;

  await db
    .insertInto('tenant_oa_responsible_for')
    .values(
      input.assignments.map((assignment) => ({
        tenant_id: input.tenantId,
        group_id: input.groupId,
        agent_membership_id: assignment.agentMembershipId,
        target_membership_id: assignment.targetMembershipId,
        created_by_membership_id: input.actorMembershipId,
      })),
    )
    .execute();
}

export async function selectResolverGrantsForMembershipSql(
  db: DbExecutor,
  input: { tenantId: string; membershipId: string; actionKey: OperationalAccessActionKey },
): Promise<OperationalAccessResolverGrantRow[]> {
  return db
    .selectFrom('tenant_group_members')
    .innerJoin('tenant_groups', (join) =>
      join
        .onRef('tenant_groups.id', '=', 'tenant_group_members.group_id')
        .onRef('tenant_groups.tenant_id', '=', 'tenant_group_members.tenant_id'),
    )
    .innerJoin('tenant_oa_group_grants', (join) =>
      join
        .onRef('tenant_oa_group_grants.group_id', '=', 'tenant_group_members.group_id')
        .onRef('tenant_oa_group_grants.tenant_id', '=', 'tenant_group_members.tenant_id'),
    )
    .select([
      'tenant_oa_group_grants.group_id as group_id',
      'tenant_oa_group_grants.action_key as action_key',
      'tenant_oa_group_grants.primary_where as primary_where',
      'tenant_oa_group_grants.which_records_key as which_records_key',
    ])
    .where('tenant_group_members.tenant_id', '=', input.tenantId)
    .where('tenant_group_members.membership_id', '=', input.membershipId)
    .where('tenant_groups.status', '=', 'ACTIVE')
    .where('tenant_groups.level', '=', 'AGENT')
    .where('tenant_oa_group_grants.action_key', '=', input.actionKey)
    .execute() as Promise<OperationalAccessResolverGrantRow[]>;
}

export async function selectResponsibleForTargetIdsForAgentSql(
  db: DbExecutor,
  input: { tenantId: string; groupId: string; agentMembershipId: string },
): Promise<string[]> {
  const rows = await db
    .selectFrom('tenant_oa_responsible_for')
    .innerJoin('memberships as target_membership', (join) =>
      join
        .onRef('target_membership.id', '=', 'tenant_oa_responsible_for.target_membership_id')
        .onRef('target_membership.tenant_id', '=', 'tenant_oa_responsible_for.tenant_id'),
    )
    .select(['tenant_oa_responsible_for.target_membership_id as target_membership_id'])
    .where('tenant_oa_responsible_for.tenant_id', '=', input.tenantId)
    .where('tenant_oa_responsible_for.group_id', '=', input.groupId)
    .where('tenant_oa_responsible_for.agent_membership_id', '=', input.agentMembershipId)
    .where('target_membership.status', '=', 'ACTIVE')
    .execute();

  return rows.map((row) => row.target_membership_id);
}

export async function selectOversightRowsForActorSql(
  db: DbExecutor,
  input: { tenantId: string; membershipId: string },
): Promise<OperationalAccessOversightRow[]> {
  return db
    .selectFrom('tenant_oa_oversight')
    .innerJoin('memberships as target_membership', (join) =>
      join
        .onRef('target_membership.id', '=', 'tenant_oa_oversight.target_membership_id')
        .onRef('target_membership.tenant_id', '=', 'tenant_oa_oversight.tenant_id'),
    )
    .select([
      'tenant_oa_oversight.overseer_membership_id as overseer_membership_id',
      'tenant_oa_oversight.target_membership_id as target_membership_id',
      'tenant_oa_oversight.includes_responsible_people as includes_responsible_people',
      'tenant_oa_oversight.reason as reason',
      'tenant_oa_oversight.review_at as review_at',
    ])
    .where('tenant_oa_oversight.tenant_id', '=', input.tenantId)
    .where('tenant_oa_oversight.overseer_membership_id', '=', input.membershipId)
    .where('target_membership.status', '=', 'ACTIVE')
    .execute() as Promise<OperationalAccessOversightRow[]>;
}

export async function selectActiveTemporaryCoverageRowsForActorSql(
  db: DbExecutor,
  input: { tenantId: string; membershipId: string; effectiveAt: Date },
): Promise<OperationalAccessTemporaryCoverageRow[]> {
  return db
    .selectFrom('tenant_oa_temporary_coverage')
    .innerJoin('memberships as covered_membership', (join) =>
      join
        .onRef('covered_membership.id', '=', 'tenant_oa_temporary_coverage.covered_membership_id')
        .onRef('covered_membership.tenant_id', '=', 'tenant_oa_temporary_coverage.tenant_id'),
    )
    .select([
      'tenant_oa_temporary_coverage.id as id',
      'tenant_oa_temporary_coverage.covering_membership_id as covering_membership_id',
      'tenant_oa_temporary_coverage.covered_membership_id as covered_membership_id',
      'tenant_oa_temporary_coverage.starts_at as starts_at',
      'tenant_oa_temporary_coverage.expires_at as expires_at',
      'tenant_oa_temporary_coverage.reason as reason',
      'tenant_oa_temporary_coverage.review_at as review_at',
    ])
    .where('tenant_oa_temporary_coverage.tenant_id', '=', input.tenantId)
    .where('tenant_oa_temporary_coverage.covering_membership_id', '=', input.membershipId)
    .where('tenant_oa_temporary_coverage.starts_at', '<=', input.effectiveAt)
    .where('tenant_oa_temporary_coverage.expires_at', '>', input.effectiveAt)
    .where('covered_membership.status', '=', 'ACTIVE')
    .execute() as Promise<OperationalAccessTemporaryCoverageRow[]>;
}

export async function selectActiveSpecialAccessRowsForActorSql(
  db: DbExecutor,
  input: {
    tenantId: string;
    membershipId: string;
    actionKey: OperationalAccessActionKey;
    effectiveAt: Date;
  },
): Promise<OperationalAccessSpecialAccessRow[]> {
  return db
    .selectFrom('tenant_oa_special_access')
    .innerJoin('memberships as target_membership', (join) =>
      join
        .onRef('target_membership.id', '=', 'tenant_oa_special_access.target_membership_id')
        .onRef('target_membership.tenant_id', '=', 'tenant_oa_special_access.tenant_id'),
    )
    .select([
      'tenant_oa_special_access.id as id',
      'tenant_oa_special_access.membership_id as membership_id',
      'tenant_oa_special_access.target_membership_id as target_membership_id',
      'tenant_oa_special_access.action_key as action_key',
      'tenant_oa_special_access.reason as reason',
      'tenant_oa_special_access.review_at as review_at',
      'tenant_oa_special_access.expires_at as expires_at',
    ])
    .where('tenant_oa_special_access.tenant_id', '=', input.tenantId)
    .where('tenant_oa_special_access.membership_id', '=', input.membershipId)
    .where('tenant_oa_special_access.action_key', '=', input.actionKey)
    .where('tenant_oa_special_access.expires_at', '>', input.effectiveAt)
    .where('tenant_oa_special_access.revoked_at', 'is', null)
    .where('target_membership.status', '=', 'ACTIVE')
    .execute() as Promise<OperationalAccessSpecialAccessRow[]>;
}

export async function selectRuntimePeopleSql(
  db: DbExecutor,
  input: { tenantId: string; membershipIds: string[] | 'ALL' },
): Promise<OperationalAccessRuntimePersonRow[]> {
  const baseSelect = () =>
    db
      .selectFrom('memberships')
      .innerJoin('users', 'users.id', 'memberships.user_id')
      .select([
        'memberships.id as membership_id',
        'users.id as user_id',
        'users.email as email',
        'users.name as name',
        'memberships.role as role',
        'memberships.status as status',
      ])
      .where('memberships.tenant_id', '=', input.tenantId)
      .where('memberships.status', '=', 'ACTIVE');

  if (input.membershipIds !== 'ALL') {
    if (input.membershipIds.length === 0) return [];
    return baseSelect()
      .where('memberships.id', 'in', input.membershipIds)
      .orderBy('users.email', 'asc')
      .execute() as Promise<OperationalAccessRuntimePersonRow[]>;
  }

  return baseSelect().orderBy('users.email', 'asc').execute() as Promise<
    OperationalAccessRuntimePersonRow[]
  >;
}

export async function insertOversightRowsSql(
  db: DbExecutor,
  input: {
    tenantId: string;
    actorMembershipId: string;
    entries: Array<{
      overseerMembershipId: string;
      targetMembershipId: string;
      includesResponsiblePeople: boolean;
      reason: string;
      reviewAt: Date;
    }>;
  },
): Promise<void> {
  await db.deleteFrom('tenant_oa_oversight').where('tenant_id', '=', input.tenantId).execute();
  if (input.entries.length === 0) return;
  await db
    .insertInto('tenant_oa_oversight')
    .values(
      input.entries.map((entry) => ({
        tenant_id: input.tenantId,
        overseer_membership_id: entry.overseerMembershipId,
        target_membership_id: entry.targetMembershipId,
        includes_responsible_people: entry.includesResponsiblePeople,
        reason: entry.reason,
        review_at: entry.reviewAt,
        created_by_membership_id: input.actorMembershipId,
      })),
    )
    .execute();
}

export async function insertTemporaryCoverageRowsSql(
  db: DbExecutor,
  input: {
    tenantId: string;
    actorMembershipId: string;
    entries: Array<{
      coveringMembershipId: string;
      coveredMembershipId: string;
      startsAt: Date;
      expiresAt: Date;
      reason: string;
      reviewAt: Date | null;
    }>;
  },
): Promise<void> {
  await db
    .deleteFrom('tenant_oa_temporary_coverage')
    .where('tenant_id', '=', input.tenantId)
    .execute();
  if (input.entries.length === 0) return;
  await db
    .insertInto('tenant_oa_temporary_coverage')
    .values(
      input.entries.map((entry) => ({
        tenant_id: input.tenantId,
        covering_membership_id: entry.coveringMembershipId,
        covered_membership_id: entry.coveredMembershipId,
        starts_at: entry.startsAt,
        expires_at: entry.expiresAt,
        reason: entry.reason,
        review_at: entry.reviewAt,
        created_by_membership_id: input.actorMembershipId,
      })),
    )
    .execute();
}

export async function insertSpecialAccessRowsSql(
  db: DbExecutor,
  input: {
    tenantId: string;
    actorMembershipId: string;
    entries: Array<{
      membershipId: string;
      targetMembershipId: string;
      actionKey: OperationalAccessActionKey;
      reason: string;
      reviewAt: Date;
      expiresAt: Date;
    }>;
  },
): Promise<void> {
  await db.deleteFrom('tenant_oa_special_access').where('tenant_id', '=', input.tenantId).execute();
  if (input.entries.length === 0) return;
  await db
    .insertInto('tenant_oa_special_access')
    .values(
      input.entries.map((entry) => ({
        tenant_id: input.tenantId,
        membership_id: entry.membershipId,
        target_membership_id: entry.targetMembershipId,
        action_key: entry.actionKey,
        reason: entry.reason,
        review_at: entry.reviewAt,
        expires_at: entry.expiresAt,
        created_by_membership_id: input.actorMembershipId,
      })),
    )
    .execute();
}

export async function selectOversightConfigSql(
  db: DbExecutor,
  tenantId: string,
): Promise<OperationalAccessOversightRow[]> {
  return db
    .selectFrom('tenant_oa_oversight')
    .select([
      'overseer_membership_id',
      'target_membership_id',
      'includes_responsible_people',
      'reason',
      'review_at',
    ])
    .where('tenant_id', '=', tenantId)
    .orderBy('created_at', 'asc')
    .execute() as Promise<OperationalAccessOversightRow[]>;
}

export async function selectTemporaryCoverageConfigSql(
  db: DbExecutor,
  tenantId: string,
): Promise<OperationalAccessTemporaryCoverageRow[]> {
  return db
    .selectFrom('tenant_oa_temporary_coverage')
    .select([
      'id',
      'covering_membership_id',
      'covered_membership_id',
      'starts_at',
      'expires_at',
      'reason',
      'review_at',
    ])
    .where('tenant_id', '=', tenantId)
    .orderBy('created_at', 'asc')
    .execute() as Promise<OperationalAccessTemporaryCoverageRow[]>;
}

export async function selectSpecialAccessConfigSql(
  db: DbExecutor,
  tenantId: string,
): Promise<OperationalAccessSpecialAccessRow[]> {
  return db
    .selectFrom('tenant_oa_special_access')
    .select([
      'id',
      'membership_id',
      'target_membership_id',
      'action_key',
      'reason',
      'review_at',
      'expires_at',
    ])
    .where('tenant_id', '=', tenantId)
    .where('revoked_at', 'is', null)
    .orderBy('created_at', 'asc')
    .execute() as Promise<OperationalAccessSpecialAccessRow[]>;
}

export async function selectRuntimePersonByMembershipIdSql(
  db: DbExecutor,
  input: { tenantId: string; membershipId: string },
): Promise<OperationalAccessRuntimePersonRow | undefined> {
  return db
    .selectFrom('memberships')
    .innerJoin('users', 'users.id', 'memberships.user_id')
    .select([
      'memberships.id as membership_id',
      'users.id as user_id',
      'users.email as email',
      'users.name as name',
      'memberships.role as role',
      'memberships.status as status',
    ])
    .where('memberships.tenant_id', '=', input.tenantId)
    .where('memberships.id', '=', input.membershipId)
    .where('memberships.status', '=', 'ACTIVE')
    .executeTakeFirst() as Promise<OperationalAccessRuntimePersonRow | undefined>;
}

export async function hasDependentOperationalAccessTablesSql(db: DbExecutor): Promise<boolean> {
  const result = await sql<{ exists: boolean }>`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name IN (
          'tenant_oa_group_grants',
          'tenant_oa_responsible_for',
          'tenant_oa_oversight',
          'tenant_oa_temporary_coverage',
          'tenant_oa_special_access'
        )
    ) AS exists
  `.execute(db);

  return result.rows[0]?.exists === true;
}
