/**
 * backend/src/modules/operational-access/operational-access.service.ts
 *
 * WHY:
 * - Application service for the Operational Access Step 3 configuration foundation.
 * - Owns validation for active Agent groups, product-defined grants, Primary Where,
 *   Which Records, and Responsible For exact-person coverage.
 *
 * RULES:
 * - No Effective Access Resolver is implemented here.
 * - Group membership alone still grants no runtime visibility.
 * - No Oversight, Temporary Coverage, or Special Access is introduced.
 */

import type { AuditRepo } from '../../shared/audit/audit.repo';
import { AuditWriter } from '../../shared/audit/audit.writer';
import type { DbExecutor } from '../../shared/db/db';
import { requireMembershipRole } from '../memberships';
import type {
  SaveOperationalAccessGroupGrantsInput,
  SaveOperationalAccessResponsibleForInput,
} from './operational-access.schemas';
import {
  auditOperationalAccessGroupGrantsSaved,
  auditOperationalAccessResponsibleForSaved,
} from './operational-access.audit';
import { OperationalAccessErrors } from './operational-access.errors';
import type { OperationalAccessRepo } from './dal/operational-access.repo';
import type {
  OperationalAccessGrantRow,
  OperationalAccessGroupRow,
  OperationalAccessMembershipRow,
  OperationalAccessResponsibleForRow,
  OperationalAccessStoredGroupRow,
} from './dal/operational-access.query-sql';
import {
  OPERATIONAL_ACCESS_ACTIONS,
  OPERATIONAL_ACCESS_PRIMARY_WHERE,
  OPERATIONAL_ACCESS_WHICH_RECORDS,
  type OperationalAccessActionCatalogItemDto,
  type OperationalAccessActionKey,
  type OperationalAccessAuditContext,
  type OperationalAccessCatalogResponse,
  type OperationalAccessGroupConfigurationDto,
  type OperationalAccessGroupConfigurationResponse,
  type OperationalAccessGroupGrantDto,
  type OperationalAccessGroupSummaryDto,
  type OperationalAccessGroupsResponse,
  type OperationalAccessPeopleResponse,
  type OperationalAccessPrimaryWhereKey,
  type OperationalAccessResponsibleForAssignmentDto,
  type OperationalAccessWhichRecordsKey,
} from './operational-access.types';

function toIso(value: Date): string {
  return value.toISOString();
}

function parseCount(value: string | number | bigint): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'bigint') return Number(value);
  return Number.parseInt(value, 10);
}

const actionCatalogByKey = new Map(
  OPERATIONAL_ACCESS_ACTIONS.map((action) => [action.key, action]),
);
const primaryWhereByKey = new Map(
  OPERATIONAL_ACCESS_PRIMARY_WHERE.map((option) => [option.key, option]),
);
const whichRecordsByKey = new Map(
  OPERATIONAL_ACCESS_WHICH_RECORDS.map((choice) => [choice.key, choice]),
);

const SAFETY_NOTES = [
  'This configuration does not change runtime visibility until backend visibility checks and module consumers ship.',
  'People & Teams group membership remains provisioning-only by itself.',
  'Assigned Areas, Oversight, Temporary Coverage, and Special Access are not shipped in this step.',
] as const;

function actionCatalogDto(): OperationalAccessActionCatalogItemDto[] {
  return OPERATIONAL_ACCESS_ACTIONS.map((action) => ({
    key: action.key,
    label: action.label,
    description: action.description,
    category: action.category,
    allowedPrimaryWhere: [...action.allowedPrimaryWhere],
    allowedWhichRecords: [...action.allowedWhichRecords],
  }));
}

function rowToGroupSummaryDto(row: OperationalAccessGroupRow): OperationalAccessGroupSummaryDto {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    level: 'AGENT',
    status: 'ACTIVE',
    memberCount: parseCount(row.member_count),
    grantCount: parseCount(row.grant_count),
    responsibleForAssignmentCount: parseCount(row.responsible_for_assignment_count),
  };
}

function rowToGrantDto(row: OperationalAccessGrantRow): OperationalAccessGroupGrantDto {
  const actionKey = row.action_key as OperationalAccessActionKey;
  const primaryWhere = row.primary_where as OperationalAccessPrimaryWhereKey;
  const whichRecordsKey = row.which_records_key as OperationalAccessWhichRecordsKey;
  const action = actionCatalogByKey.get(actionKey);
  const where = primaryWhereByKey.get(primaryWhere);
  const records = whichRecordsByKey.get(whichRecordsKey);

  return {
    id: row.id,
    actionKey,
    actionLabel: action?.label ?? row.action_key,
    primaryWhere,
    primaryWhereLabel: where?.label ?? row.primary_where,
    whichRecordsKey,
    whichRecordsLabel: records?.label ?? row.which_records_key,
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
  };
}

function rowToResponsibleForDto(
  row: OperationalAccessResponsibleForRow,
): OperationalAccessResponsibleForAssignmentDto {
  return {
    agentMembershipId: row.agent_membership_id,
    agentUserId: row.agent_user_id,
    agentEmail: row.agent_email,
    agentName: row.agent_name,
    targetMembershipId: row.target_membership_id,
    targetUserId: row.target_user_id,
    targetEmail: row.target_email,
    targetName: row.target_name,
    createdAt: toIso(row.created_at),
  };
}

function membershipToPersonDto(row: OperationalAccessMembershipRow) {
  const role = requireMembershipRole(row.role);

  return {
    membershipId: row.membership_id,
    userId: row.user_id,
    email: row.email,
    name: row.name,
    role,
    status: 'ACTIVE' as const,
    isAgent: role === 'AGENT',
  };
}

function groupToAuditSummary(group: OperationalAccessStoredGroupRow | OperationalAccessGroupRow) {
  return {
    id: group.id,
    name: group.name,
    level: 'AGENT' as const,
  };
}

export class OperationalAccessService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      auditRepo: AuditRepo;
      repo: OperationalAccessRepo;
    },
  ) {}

  async getCatalog(tenantId: string): Promise<OperationalAccessCatalogResponse> {
    await this.assertCapabilityEnabled(tenantId);
    return {
      catalog: {
        actions: actionCatalogDto(),
        primaryWhere: OPERATIONAL_ACCESS_PRIMARY_WHERE.map((option) => ({ ...option })),
        whichRecords: OPERATIONAL_ACCESS_WHICH_RECORDS.map((choice) => ({ ...choice })),
        coverage: {
          assignedAreas: {
            available: false,
            reason:
              'Assigned Areas requires stable employer/location pair IDs. Current Account Settings stores employer and location names as tenant configuration values only.',
          },
          responsibleFor: {
            available: true,
            targetType: 'tenant_membership',
            reason:
              'Responsible For can safely use active tenant membership IDs as stable exact-person targets.',
          },
        },
        deferred: [
          'Assigned Areas coverage table and UI are deferred until stable employer/location pair IDs exist.',
          'Oversight is deferred.',
          'Temporary Coverage is deferred.',
          'Special Access / Person Exceptions are deferred.',
          'Backend runtime visibility decisions and module consumers are deferred.',
        ],
      },
    };
  }

  async listGroups(tenantId: string): Promise<OperationalAccessGroupsResponse> {
    await this.assertCapabilityEnabled(tenantId);
    const rows = await this.deps.repo.listActiveAgentGroups(tenantId);
    return { groups: rows.map(rowToGroupSummaryDto) };
  }

  async listPeople(tenantId: string): Promise<OperationalAccessPeopleResponse> {
    await this.assertCapabilityEnabled(tenantId);
    const rows = await this.deps.repo.listActivePeople(tenantId);
    return { people: rows.map(membershipToPersonDto) };
  }

  async getGroupConfiguration(
    tenantId: string,
    groupId: string,
  ): Promise<OperationalAccessGroupConfigurationResponse> {
    await this.assertCapabilityEnabled(tenantId);
    const configuration = await this.loadGroupConfiguration(this.deps.repo, tenantId, groupId);
    return { groupConfiguration: configuration };
  }

  async saveGroupGrants(
    auth: OperationalAccessAuditContext,
    groupId: string,
    input: SaveOperationalAccessGroupGrantsInput,
  ): Promise<OperationalAccessGroupConfigurationResponse> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.repo.withDb(trx);
      await this.assertCapabilityEnabled(auth.tenantId, repo);
      const group = await this.assertWritableAgentGroup(repo, auth.tenantId, groupId);
      this.validateGrantInput(input);

      const before = (await repo.listGroupGrants({ tenantId: auth.tenantId, groupId })).map(
        rowToGrantDto,
      );

      await repo.replaceGroupGrants({
        tenantId: auth.tenantId,
        groupId,
        actorMembershipId: auth.membershipId,
        grants: input.grants,
      });

      const after = (await repo.listGroupGrants({ tenantId: auth.tenantId, groupId })).map(
        rowToGrantDto,
      );

      const writer = this.buildAuditWriter(trx, auth);
      await auditOperationalAccessGroupGrantsSaved(writer, {
        group: groupToAuditSummary(group),
        before,
        after,
        source: 'OperationalAccessService.saveGroupGrants',
      });

      return {
        groupConfiguration: await this.loadGroupConfiguration(repo, auth.tenantId, groupId),
      };
    });
  }

  async saveResponsibleFor(
    auth: OperationalAccessAuditContext,
    groupId: string,
    input: SaveOperationalAccessResponsibleForInput,
  ): Promise<OperationalAccessGroupConfigurationResponse> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.repo.withDb(trx);
      await this.assertCapabilityEnabled(auth.tenantId, repo);
      const group = await this.assertWritableAgentGroup(repo, auth.tenantId, groupId);
      await this.validateResponsibleForInput(repo, auth.tenantId, groupId, input);

      const before = (await repo.listResponsibleFor({ tenantId: auth.tenantId, groupId })).map(
        rowToResponsibleForDto,
      );

      await repo.replaceResponsibleFor({
        tenantId: auth.tenantId,
        groupId,
        actorMembershipId: auth.membershipId,
        assignments: input.assignments,
      });

      const after = (await repo.listResponsibleFor({ tenantId: auth.tenantId, groupId })).map(
        rowToResponsibleForDto,
      );

      const writer = this.buildAuditWriter(trx, auth);
      await auditOperationalAccessResponsibleForSaved(writer, {
        group: groupToAuditSummary(group),
        before,
        after,
        source: 'OperationalAccessService.saveResponsibleFor',
      });

      return {
        groupConfiguration: await this.loadGroupConfiguration(repo, auth.tenantId, groupId),
      };
    });
  }

  private async assertCapabilityEnabled(
    tenantId: string,
    repo: OperationalAccessRepo = this.deps.repo,
  ): Promise<void> {
    const row = await repo.getTenantCapability(tenantId);
    if (!row?.operational_access_enabled) throw OperationalAccessErrors.capabilityDisabled();
  }

  private async assertWritableAgentGroup(
    repo: OperationalAccessRepo,
    tenantId: string,
    groupId: string,
  ): Promise<OperationalAccessStoredGroupRow> {
    const group = await repo.getStoredGroup({ tenantId, groupId });
    if (!group) throw OperationalAccessErrors.groupNotFound(groupId);
    if (group.status !== 'ACTIVE' || group.level !== 'AGENT') {
      throw OperationalAccessErrors.groupMustBeActiveAgent(groupId);
    }

    return group;
  }

  private async loadGroupConfiguration(
    repo: OperationalAccessRepo,
    tenantId: string,
    groupId: string,
  ): Promise<OperationalAccessGroupConfigurationDto> {
    const group = await repo.getGroup({ tenantId, groupId });
    if (!group) throw OperationalAccessErrors.groupNotFound(groupId);
    if (group.status !== 'ACTIVE' || group.level !== 'AGENT') {
      throw OperationalAccessErrors.groupMustBeActiveAgent(groupId);
    }

    const [grants, responsibleFor] = await Promise.all([
      repo.listGroupGrants({ tenantId, groupId }),
      repo.listResponsibleFor({ tenantId, groupId }),
    ]);

    return {
      group: rowToGroupSummaryDto(group),
      grants: grants.map(rowToGrantDto),
      responsibleFor: responsibleFor.map(rowToResponsibleForDto),
      safety: {
        runtimeVisibilityChanged: false,
        effectiveAccessResolverShipped: false,
        notes: [...SAFETY_NOTES],
      },
    };
  }

  private validateGrantInput(input: SaveOperationalAccessGroupGrantsInput): void {
    const seenActions = new Set<string>();

    for (const grant of input.grants) {
      if (seenActions.has(grant.actionKey)) {
        throw OperationalAccessErrors.duplicateGrant(grant.actionKey);
      }
      seenActions.add(grant.actionKey);

      const action = actionCatalogByKey.get(grant.actionKey);
      if (!action) throw OperationalAccessErrors.invalidActionKey(grant.actionKey);
      if (!primaryWhereByKey.has(grant.primaryWhere)) {
        throw OperationalAccessErrors.invalidPrimaryWhere(grant.primaryWhere);
      }
      if (!whichRecordsByKey.has(grant.whichRecordsKey)) {
        throw OperationalAccessErrors.invalidWhichRecords(grant.whichRecordsKey);
      }

      if (
        !(action.allowedPrimaryWhere as readonly OperationalAccessPrimaryWhereKey[]).includes(
          grant.primaryWhere,
        ) ||
        !(action.allowedWhichRecords as readonly OperationalAccessWhichRecordsKey[]).includes(
          grant.whichRecordsKey,
        )
      ) {
        throw OperationalAccessErrors.invalidGrantCombination(grant);
      }
    }
  }

  private async validateResponsibleForInput(
    repo: OperationalAccessRepo,
    tenantId: string,
    groupId: string,
    input: SaveOperationalAccessResponsibleForInput,
  ): Promise<void> {
    const seen = new Set<string>();

    for (const assignment of input.assignments) {
      const key = `${assignment.agentMembershipId}:${assignment.targetMembershipId}`;
      if (seen.has(key)) {
        throw OperationalAccessErrors.duplicateResponsibleForAssignment(
          assignment.agentMembershipId,
          assignment.targetMembershipId,
        );
      }
      seen.add(key);

      if (assignment.agentMembershipId === assignment.targetMembershipId) {
        throw OperationalAccessErrors.selfResponsibleForNotAllowed(assignment.agentMembershipId);
      }

      const agent = await repo.getActiveMembership({
        tenantId,
        membershipId: assignment.agentMembershipId,
      });
      if (!agent) throw OperationalAccessErrors.membershipNotFound(assignment.agentMembershipId);
      if (requireMembershipRole(agent.role) !== 'AGENT') {
        throw OperationalAccessErrors.agentMembershipRequired(assignment.agentMembershipId);
      }

      const agentGroupMember = await repo.getActiveGroupMember({
        tenantId,
        groupId,
        membershipId: assignment.agentMembershipId,
      });
      if (!agentGroupMember) {
        throw OperationalAccessErrors.agentMustBeGroupMember(assignment.agentMembershipId, groupId);
      }

      const target = await repo.getActiveMembership({
        tenantId,
        membershipId: assignment.targetMembershipId,
      });
      if (!target) throw OperationalAccessErrors.membershipNotFound(assignment.targetMembershipId);
      if (target.status !== 'ACTIVE') {
        throw OperationalAccessErrors.targetMembershipRequired(assignment.targetMembershipId);
      }
    }
  }

  private buildAuditWriter(db: DbExecutor, context: OperationalAccessAuditContext): AuditWriter {
    return new AuditWriter(this.deps.auditRepo.withDb(db), {
      requestId: context.requestId,
      ip: context.ip,
      userAgent: context.userAgent,
      tenantId: context.tenantId,
      userId: context.userId,
      membershipId: context.membershipId,
    });
  }
}
