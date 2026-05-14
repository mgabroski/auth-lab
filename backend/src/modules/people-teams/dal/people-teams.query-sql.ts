/**
 * backend/src/modules/people-teams/dal/people-teams.query-sql.ts
 *
 * WHY:
 * - Raw Kysely read implementations for People & Teams.
 * - Keeps tenant scoping at the query boundary.
 *
 * RULES:
 * - No AppError.
 * - No business logic.
 * - No Operational Access joins or permission/grant concepts.
 * - Every query is scoped by tenant_id from the authenticated session.
 */

import type { DbExecutor } from '../../../shared/db/db';

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
