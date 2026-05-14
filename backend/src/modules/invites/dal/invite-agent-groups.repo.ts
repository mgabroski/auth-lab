/**
 * backend/src/modules/invites/dal/invite-agent-groups.repo.ts
 *
 * WHY:
 * - Write-side repository for provisioning-only Agent invite group persistence.
 * - Keeps invite flows from writing tenant_group_members directly when an Agent
 *   invite is accepted/registered.
 *
 * RULES:
 * - No transactions started here.
 * - No AppError or business validation.
 * - No Operational Access grants, scopes, Person Exceptions, or resolver work.
 */

import type { DbExecutor } from '../../../shared/db/db';

export class InviteAgentGroupsRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): InviteAgentGroupsRepo {
    return new InviteAgentGroupsRepo(db);
  }

  async insertInviteAgentGroups(input: {
    tenantId: string;
    inviteId: string;
    groupIds: readonly string[];
  }): Promise<void> {
    if (input.groupIds.length === 0) return;

    await this.db
      .insertInto('invite_agent_groups')
      .values(
        input.groupIds.map((groupId) => ({
          tenant_id: input.tenantId,
          invite_id: input.inviteId,
          group_id: groupId,
        })),
      )
      .onConflict((oc) => oc.columns(['invite_id', 'group_id']).doNothing())
      .execute();
  }

  async attachAgentGroupsToMembership(input: {
    tenantId: string;
    inviteId: string;
    membershipId: string;
    addedByMembershipId: string | null;
  }): Promise<Array<{ groupId: string }>> {
    const assigned = await this.db
      .selectFrom('invite_agent_groups')
      .select(['group_id'])
      .where('tenant_id', '=', input.tenantId)
      .where('invite_id', '=', input.inviteId)
      .execute();

    if (assigned.length === 0) return [];

    const inserted = await this.db
      .insertInto('tenant_group_members')
      .values(
        assigned.map((row) => ({
          tenant_id: input.tenantId,
          group_id: row.group_id,
          membership_id: input.membershipId,
          added_by_membership_id: input.addedByMembershipId,
        })),
      )
      .onConflict((oc) => oc.columns(['group_id', 'membership_id']).doNothing())
      .returning(['group_id'])
      .execute();

    return inserted.map((row) => ({ groupId: row.group_id }));
  }
}
