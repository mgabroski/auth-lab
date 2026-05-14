/**
 * backend/src/modules/people-teams/dal/people-teams.query-sql.ts
 *
 * WHY:
 * - Raw Kysely implementations for People & Teams.
 * - Keeps tenant scoping at the query boundary.
 *
 * RULES:
 * - No AppError.
 * - No business logic.
 * - No Operational Access joins or permission/grant concepts.
 * - Every query is scoped by tenant_id from the authenticated session.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { PeopleTeamGroupLevel } from '../people-teams.types';

export type PeopleTeamGroupRow = {
  id: string;
  name: string;
  normalized_name: string;
  description: string | null;
  level: string;
  status: string;
  member_count: string | number | bigint;
  created_at: Date;
  updated_at: Date;
  archived_at: Date | null;
};

export type PeopleTeamStoredGroupRow = {
  id: string;
  tenant_id: string;
  name: string;
  normalized_name: string;
  description: string | null;
  level: string;
  status: string;
  created_at: Date;
  updated_at: Date;
  archived_at: Date | null;
};

const GROUP_SELECT_COLUMNS = [
  'id',
  'tenant_id',
  'name',
  'normalized_name',
  'description',
  'level',
  'status',
  'created_at',
  'updated_at',
  'archived_at',
] as const;

export async function selectActiveGroupsByTenantSql(
  db: DbExecutor,
  tenantId: string,
): Promise<PeopleTeamGroupRow[]> {
  return db
    .selectFrom('tenant_groups')
    .leftJoin('tenant_group_members', (join) =>
      join
        .onRef('tenant_group_members.group_id', '=', 'tenant_groups.id')
        .onRef('tenant_group_members.tenant_id', '=', 'tenant_groups.tenant_id'),
    )
    .select((eb) => [
      'tenant_groups.id as id',
      'tenant_groups.name as name',
      'tenant_groups.normalized_name as normalized_name',
      'tenant_groups.description as description',
      'tenant_groups.level as level',
      'tenant_groups.status as status',
      eb.fn.count<string>('tenant_group_members.membership_id').as('member_count'),
      'tenant_groups.created_at as created_at',
      'tenant_groups.updated_at as updated_at',
      'tenant_groups.archived_at as archived_at',
    ])
    .where('tenant_groups.tenant_id', '=', tenantId)
    .where('tenant_groups.status', '=', 'ACTIVE')
    .groupBy([
      'tenant_groups.id',
      'tenant_groups.name',
      'tenant_groups.normalized_name',
      'tenant_groups.description',
      'tenant_groups.level',
      'tenant_groups.status',
      'tenant_groups.created_at',
      'tenant_groups.updated_at',
      'tenant_groups.archived_at',
    ])
    .orderBy('tenant_groups.normalized_name', 'asc')
    .execute() as Promise<PeopleTeamGroupRow[]>;
}

export async function selectGroupByIdForTenantSql(
  db: DbExecutor,
  tenantId: string,
  groupId: string,
): Promise<PeopleTeamGroupRow | undefined> {
  return db
    .selectFrom('tenant_groups')
    .leftJoin('tenant_group_members', (join) =>
      join
        .onRef('tenant_group_members.group_id', '=', 'tenant_groups.id')
        .onRef('tenant_group_members.tenant_id', '=', 'tenant_groups.tenant_id'),
    )
    .select((eb) => [
      'tenant_groups.id as id',
      'tenant_groups.name as name',
      'tenant_groups.normalized_name as normalized_name',
      'tenant_groups.description as description',
      'tenant_groups.level as level',
      'tenant_groups.status as status',
      eb.fn.count<string>('tenant_group_members.membership_id').as('member_count'),
      'tenant_groups.created_at as created_at',
      'tenant_groups.updated_at as updated_at',
      'tenant_groups.archived_at as archived_at',
    ])
    .where('tenant_groups.tenant_id', '=', tenantId)
    .where('tenant_groups.id', '=', groupId)
    .groupBy([
      'tenant_groups.id',
      'tenant_groups.name',
      'tenant_groups.normalized_name',
      'tenant_groups.description',
      'tenant_groups.level',
      'tenant_groups.status',
      'tenant_groups.created_at',
      'tenant_groups.updated_at',
      'tenant_groups.archived_at',
    ])
    .executeTakeFirst() as Promise<PeopleTeamGroupRow | undefined>;
}

export async function selectStoredGroupByIdForTenantSql(
  db: DbExecutor,
  tenantId: string,
  groupId: string,
): Promise<PeopleTeamStoredGroupRow | undefined> {
  return db
    .selectFrom('tenant_groups')
    .select(GROUP_SELECT_COLUMNS)
    .where('tenant_id', '=', tenantId)
    .where('id', '=', groupId)
    .executeTakeFirst() as Promise<PeopleTeamStoredGroupRow | undefined>;
}

export async function selectGroupByNormalizedNameSql(
  db: DbExecutor,
  tenantId: string,
  normalizedName: string,
): Promise<{ id: string } | undefined> {
  return db
    .selectFrom('tenant_groups')
    .select(['id'])
    .where('tenant_id', '=', tenantId)
    .where('normalized_name', '=', normalizedName)
    .executeTakeFirst();
}

export async function insertGroupSql(
  db: DbExecutor,
  input: {
    tenantId: string;
    name: string;
    normalizedName: string;
    description: string | null;
    level: PeopleTeamGroupLevel;
    actorMembershipId: string;
  },
): Promise<PeopleTeamStoredGroupRow> {
  return db
    .insertInto('tenant_groups')
    .values({
      tenant_id: input.tenantId,
      name: input.name,
      normalized_name: input.normalizedName,
      description: input.description,
      level: input.level,
      status: 'ACTIVE',
      created_by_membership_id: input.actorMembershipId,
      updated_by_membership_id: input.actorMembershipId,
    })
    .returning(GROUP_SELECT_COLUMNS)
    .executeTakeFirstOrThrow() as Promise<PeopleTeamStoredGroupRow>;
}

export async function updateActiveGroupSql(
  db: DbExecutor,
  input: {
    tenantId: string;
    groupId: string;
    name: string;
    normalizedName: string;
    description: string | null;
    level: PeopleTeamGroupLevel;
    actorMembershipId: string;
  },
): Promise<PeopleTeamStoredGroupRow | undefined> {
  return db
    .updateTable('tenant_groups')
    .set({
      name: input.name,
      normalized_name: input.normalizedName,
      description: input.description,
      level: input.level,
      updated_by_membership_id: input.actorMembershipId,
      updated_at: new Date(),
    })
    .where('tenant_id', '=', input.tenantId)
    .where('id', '=', input.groupId)
    .where('status', '=', 'ACTIVE')
    .returning(GROUP_SELECT_COLUMNS)
    .executeTakeFirst() as Promise<PeopleTeamStoredGroupRow | undefined>;
}

export async function archiveActiveGroupSql(
  db: DbExecutor,
  input: {
    tenantId: string;
    groupId: string;
    actorMembershipId: string;
  },
): Promise<PeopleTeamStoredGroupRow | undefined> {
  const now = new Date();

  return db
    .updateTable('tenant_groups')
    .set({
      status: 'ARCHIVED',
      archived_at: now,
      archived_by_membership_id: input.actorMembershipId,
      updated_by_membership_id: input.actorMembershipId,
      updated_at: now,
    })
    .where('tenant_id', '=', input.tenantId)
    .where('id', '=', input.groupId)
    .where('status', '=', 'ACTIVE')
    .returning(GROUP_SELECT_COLUMNS)
    .executeTakeFirst() as Promise<PeopleTeamStoredGroupRow | undefined>;
}

export type PeopleTeamPersonRow = {
  membership_id: string;
  user_id: string;
  email: string;
  name: string | null;
  role: string;
  status: string;
};

export async function selectActivePeopleByTenantSql(
  db: DbExecutor,
  tenantId: string,
): Promise<PeopleTeamPersonRow[]> {
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
    .execute() as Promise<PeopleTeamPersonRow[]>;
}

export type PeopleTeamGroupMemberRow = {
  membership_id: string;
  user_id: string;
  email: string;
  name: string | null;
  role: string;
  status: string;
  created_at: Date;
};

export async function selectGroupMembersSql(
  db: DbExecutor,
  input: { tenantId: string; groupId: string },
): Promise<PeopleTeamGroupMemberRow[]> {
  return db
    .selectFrom('tenant_group_members')
    .innerJoin('memberships', (join) =>
      join
        .onRef('memberships.id', '=', 'tenant_group_members.membership_id')
        .onRef('memberships.tenant_id', '=', 'tenant_group_members.tenant_id'),
    )
    .innerJoin('users', 'users.id', 'memberships.user_id')
    .select([
      'memberships.id as membership_id',
      'users.id as user_id',
      'users.email as email',
      'users.name as name',
      'memberships.role as role',
      'memberships.status as status',
      'tenant_group_members.created_at as created_at',
    ])
    .where('tenant_group_members.tenant_id', '=', input.tenantId)
    .where('tenant_group_members.group_id', '=', input.groupId)
    .orderBy('users.email', 'asc')
    .execute() as Promise<PeopleTeamGroupMemberRow[]>;
}

export async function selectGroupMemberSql(
  db: DbExecutor,
  input: { tenantId: string; groupId: string; membershipId: string },
): Promise<PeopleTeamGroupMemberRow | undefined> {
  return db
    .selectFrom('tenant_group_members')
    .innerJoin('memberships', (join) =>
      join
        .onRef('memberships.id', '=', 'tenant_group_members.membership_id')
        .onRef('memberships.tenant_id', '=', 'tenant_group_members.tenant_id'),
    )
    .innerJoin('users', 'users.id', 'memberships.user_id')
    .select([
      'memberships.id as membership_id',
      'users.id as user_id',
      'users.email as email',
      'users.name as name',
      'memberships.role as role',
      'memberships.status as status',
      'tenant_group_members.created_at as created_at',
    ])
    .where('tenant_group_members.tenant_id', '=', input.tenantId)
    .where('tenant_group_members.group_id', '=', input.groupId)
    .where('tenant_group_members.membership_id', '=', input.membershipId)
    .executeTakeFirst() as Promise<PeopleTeamGroupMemberRow | undefined>;
}

export type PeopleTeamMembershipRow = {
  membership_id: string;
  user_id: string;
  email: string;
  name: string | null;
  role: string;
  status: string;
};

export async function selectMembershipByTenantSql(
  db: DbExecutor,
  input: { tenantId: string; membershipId: string },
): Promise<PeopleTeamMembershipRow | undefined> {
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
    .executeTakeFirst() as Promise<PeopleTeamMembershipRow | undefined>;
}

export async function selectExistingGroupMemberSql(
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

export async function insertGroupMemberSql(
  db: DbExecutor,
  input: {
    tenantId: string;
    groupId: string;
    membershipId: string;
    actorMembershipId: string;
  },
): Promise<void> {
  await db
    .insertInto('tenant_group_members')
    .values({
      tenant_id: input.tenantId,
      group_id: input.groupId,
      membership_id: input.membershipId,
      added_by_membership_id: input.actorMembershipId,
    })
    .execute();
}

export async function deleteGroupMemberSql(
  db: DbExecutor,
  input: { tenantId: string; groupId: string; membershipId: string },
): Promise<{ membership_id: string } | undefined> {
  return db
    .deleteFrom('tenant_group_members')
    .where('tenant_id', '=', input.tenantId)
    .where('group_id', '=', input.groupId)
    .where('membership_id', '=', input.membershipId)
    .returning(['membership_id'])
    .executeTakeFirst();
}
