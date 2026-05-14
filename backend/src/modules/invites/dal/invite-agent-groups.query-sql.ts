/**
 * backend/src/modules/invites/dal/invite-agent-groups.query-sql.ts
 *
 * WHY:
 * - Read-side access for provisioning-only Agent invite group assignments.
 * - Keeps tenant scoping and safe group metadata shaping out of invite flows.
 *
 * RULES:
 * - No AppError.
 * - No Operational Access grants, scopes, Person Exceptions, or resolver work.
 * - Cross-tenant group IDs simply do not appear in tenant-scoped reads.
 */

import type { DbExecutor } from '../../../shared/db/db';

export type InviteAgentGroupRow = {
  id: string;
  name: string;
  level: string;
  status: string;
};

export type InviteAgentGroupByInviteRow = InviteAgentGroupRow & {
  invite_id: string;
};

export async function selectInviteAgentGroupsByIdsSql(
  db: DbExecutor,
  input: { tenantId: string; groupIds: readonly string[] },
): Promise<InviteAgentGroupRow[]> {
  if (input.groupIds.length === 0) return [];

  return db
    .selectFrom('tenant_groups')
    .select(['id', 'name', 'level', 'status'])
    .where('tenant_id', '=', input.tenantId)
    .where('id', 'in', [...input.groupIds])
    .execute() as Promise<InviteAgentGroupRow[]>;
}

export async function selectInviteAgentGroupsSql(
  db: DbExecutor,
  input: { tenantId: string; inviteId: string },
): Promise<InviteAgentGroupRow[]> {
  return db
    .selectFrom('invite_agent_groups')
    .innerJoin('tenant_groups', (join) =>
      join
        .onRef('tenant_groups.id', '=', 'invite_agent_groups.group_id')
        .onRef('tenant_groups.tenant_id', '=', 'invite_agent_groups.tenant_id'),
    )
    .select([
      'tenant_groups.id as id',
      'tenant_groups.name as name',
      'tenant_groups.level as level',
      'tenant_groups.status as status',
    ])
    .where('invite_agent_groups.tenant_id', '=', input.tenantId)
    .where('invite_agent_groups.invite_id', '=', input.inviteId)
    .orderBy('tenant_groups.name', 'asc')
    .execute() as Promise<InviteAgentGroupRow[]>;
}

export async function selectInviteAgentGroupsForInvitesSql(
  db: DbExecutor,
  input: { tenantId: string; inviteIds: readonly string[] },
): Promise<InviteAgentGroupByInviteRow[]> {
  if (input.inviteIds.length === 0) return [];

  return db
    .selectFrom('invite_agent_groups')
    .innerJoin('tenant_groups', (join) =>
      join
        .onRef('tenant_groups.id', '=', 'invite_agent_groups.group_id')
        .onRef('tenant_groups.tenant_id', '=', 'invite_agent_groups.tenant_id'),
    )
    .select([
      'invite_agent_groups.invite_id as invite_id',
      'tenant_groups.id as id',
      'tenant_groups.name as name',
      'tenant_groups.level as level',
      'tenant_groups.status as status',
    ])
    .where('invite_agent_groups.tenant_id', '=', input.tenantId)
    .where('invite_agent_groups.invite_id', 'in', [...input.inviteIds])
    .orderBy('tenant_groups.name', 'asc')
    .execute() as Promise<InviteAgentGroupByInviteRow[]>;
}
