/**
 * backend/src/modules/invites/helpers/agent-invite-groups.ts
 *
 * WHY:
 * - Centralizes Agent invite group validation and DTO shaping.
 * - Agent group assignment is provisioning-only: it records group membership to
 *   apply during invite activation. It does not grant Operational Access.
 *
 * RULES:
 * - AGENT invites require at least one active Agent group.
 * - ADMIN / USER invites must not carry Agent group IDs.
 * - Cross-tenant IDs fail with the same generic validation as missing/invalid IDs.
 * - Group level remains classification only; it never grants /admin access.
 */

import type { AuditWriter } from '../../../shared/audit/audit.writer';
import type { DbExecutor } from '../../../shared/db/db';
import type { Invite, InviteRole, InviteSummary } from '../invite.types';
import { AdminInviteErrors } from '../admin/admin-invite.errors';
import { InviteErrors } from '../invite.errors';
import { InviteAgentGroupsRepo } from '../dal/invite-agent-groups.repo';
import {
  selectInviteAgentGroupsByIdsSql,
  selectInviteAgentGroupsForInvitesSql,
  selectInviteAgentGroupsSql,
  type InviteAgentGroupByInviteRow,
  type InviteAgentGroupRow,
} from '../dal/invite-agent-groups.query-sql';
import type { MembershipRole, MembershipStatus } from '../../memberships/membership.types';

export type AgentInviteGroupSummary = {
  id: string;
  name: string;
  level: 'AGENT';
  status: 'ACTIVE';
};

export type AgentInviteGroupUnsafeSummary = {
  id: string;
  name: string;
  level: string;
  status: string;
};

function uniqueGroupIds(groupIds: readonly string[] | undefined): string[] {
  if (!groupIds) return [];
  return [...new Set(groupIds)];
}

function hasDuplicateGroupIds(groupIds: readonly string[] | undefined): boolean {
  if (!groupIds) return false;
  return new Set(groupIds).size !== groupIds.length;
}

function rowToSafeSummary(row: InviteAgentGroupRow): AgentInviteGroupSummary {
  return {
    id: row.id,
    name: row.name,
    level: 'AGENT',
    status: 'ACTIVE',
  };
}

function rowToUnsafeSummary(row: InviteAgentGroupRow): AgentInviteGroupUnsafeSummary {
  return {
    id: row.id,
    name: row.name,
    level: row.level,
    status: row.status,
  };
}

function areAllActiveAgentGroups(rows: readonly InviteAgentGroupRow[]): boolean {
  return rows.every((row) => row.level === 'AGENT' && row.status === 'ACTIVE');
}

export function withAgentGroups(
  invite: InviteSummary,
  groups: readonly AgentInviteGroupUnsafeSummary[],
): InviteSummary {
  if (invite.role !== 'AGENT') return invite;
  return {
    ...invite,
    agentGroups: groups.map((group) => ({ ...group })),
  };
}

export function groupAgentRowsByInviteId(
  rows: readonly InviteAgentGroupByInviteRow[],
): Map<string, AgentInviteGroupUnsafeSummary[]> {
  const map = new Map<string, AgentInviteGroupUnsafeSummary[]>();

  for (const row of rows) {
    const existing = map.get(row.invite_id) ?? [];
    existing.push(rowToUnsafeSummary(row));
    map.set(row.invite_id, existing);
  }

  return map;
}

export async function loadAgentGroupsForInviteSummaries(
  db: DbExecutor,
  input: { tenantId: string; invites: readonly InviteSummary[] },
): Promise<Map<string, AgentInviteGroupUnsafeSummary[]>> {
  const agentInviteIds = input.invites
    .filter((invite) => invite.role === 'AGENT')
    .map((invite) => invite.id);

  const rows = await selectInviteAgentGroupsForInvitesSql(db, {
    tenantId: input.tenantId,
    inviteIds: agentInviteIds,
  });

  return groupAgentRowsByInviteId(rows);
}

export async function validateAgentGroupSelectionForAdminInvite(
  db: DbExecutor,
  input: {
    tenantId: string;
    role: InviteRole;
    agentGroupIds?: readonly string[];
  },
): Promise<AgentInviteGroupSummary[]> {
  const normalizedGroupIds = uniqueGroupIds(input.agentGroupIds);

  if (input.role !== 'AGENT') {
    if (input.agentGroupIds !== undefined) {
      throw AdminInviteErrors.agentGroupsOnlyForAgent();
    }
    return [];
  }

  if (normalizedGroupIds.length === 0) {
    throw AdminInviteErrors.agentGroupsRequired();
  }

  if (hasDuplicateGroupIds(input.agentGroupIds)) {
    throw AdminInviteErrors.invalidAgentGroups();
  }

  const rows = await selectInviteAgentGroupsByIdsSql(db, {
    tenantId: input.tenantId,
    groupIds: normalizedGroupIds,
  });

  if (rows.length !== normalizedGroupIds.length || !areAllActiveAgentGroups(rows)) {
    throw AdminInviteErrors.invalidAgentGroups();
  }

  const byId = new Map(rows.map((row) => [row.id, row]));
  return normalizedGroupIds.map((groupId) => {
    const row = byId.get(groupId);
    if (!row) throw AdminInviteErrors.invalidAgentGroups();
    return rowToSafeSummary(row);
  });
}

export async function requireValidAgentGroupsForAdminResend(
  db: DbExecutor,
  input: { tenantId: string; inviteId: string; role: InviteRole },
): Promise<AgentInviteGroupSummary[]> {
  if (input.role !== 'AGENT') return [];

  const rows = await selectInviteAgentGroupsSql(db, {
    tenantId: input.tenantId,
    inviteId: input.inviteId,
  });

  if (rows.length === 0 || !areAllActiveAgentGroups(rows)) {
    throw AdminInviteErrors.invalidAgentGroupsForResend();
  }

  return rows.map(rowToSafeSummary);
}

export async function requireValidAgentGroupsForInviteActivation(
  db: DbExecutor,
  invite: Invite,
): Promise<AgentInviteGroupSummary[]> {
  if (invite.role !== 'AGENT') return [];

  const rows = await selectInviteAgentGroupsSql(db, {
    tenantId: invite.tenantId,
    inviteId: invite.id,
  });

  if (rows.length === 0 || !areAllActiveAgentGroups(rows)) {
    throw InviteErrors.agentInviteGroupsInvalid();
  }

  return rows.map(rowToSafeSummary);
}

export async function attachAgentInviteGroupsToMembership(input: {
  trx: DbExecutor;
  tenantId: string;
  invite: Invite;
  membership: {
    id: string;
    userId: string;
    role: MembershipRole;
    status: MembershipStatus;
  };
  user: { email: string; name: string | null };
  audit: AuditWriter;
}): Promise<void> {
  if (input.invite.role !== 'AGENT') return;

  await requireValidAgentGroupsForInviteActivation(input.trx, input.invite);

  const repo = new InviteAgentGroupsRepo(input.trx);
  const inserted = await repo.attachAgentGroupsToMembership({
    tenantId: input.tenantId,
    inviteId: input.invite.id,
    membershipId: input.membership.id,
    addedByMembershipId: null,
  });

  for (const row of inserted) {
    await input.audit.append('people_teams.member_added', {
      source: 'AgentInviteProvisioning.attachAgentGroupsToMembership',
      member: {
        groupId: row.groupId,
        membershipId: input.membership.id,
        userId: input.membership.userId,
        email: input.user.email,
        name: input.user.name,
        role: input.membership.role,
        status: input.membership.status,
      },
    });
  }
}
