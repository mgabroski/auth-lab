/**
 * backend/src/modules/operational-access/operational-access.service.ts
 *
 * WHY:
 * - Application service for Operational Access configuration plus the narrow
 *   resolver proof surface.
 * - Owns validation for active Agent groups, product-defined grants, Primary Where,
 *   Which Records, Responsible For, Oversight, Temporary Coverage, and Special Access.
 *
 * RULES:
 * - Backend owns effective access decisions.
 * - Group membership alone grants nothing without a product-defined grant and
 *   matching scope/coverage or Special Access.
 * - The first consumer is a narrow people/Personal Card proof surface only.
 */

import type { AuditRepo } from '../../shared/audit/audit.repo';
import { AuditWriter } from '../../shared/audit/audit.writer';
import type { DbExecutor } from '../../shared/db/db';
import { requireMembershipRole } from '../memberships';
import type {
  SaveOperationalAccessGroupGrantsInput,
  SaveOperationalAccessOversightInput,
  SaveOperationalAccessResponsibleForInput,
  SaveOperationalAccessSpecialAccessInput,
  SaveOperationalAccessTemporaryCoverageInput,
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
  OperationalAccessRuntimePersonRow,
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
  type OperationalAccessAdvancedCoverageResponse,
  type OperationalAccessDecisionDto,
  type OperationalAccessFieldVisibility,
  type OperationalAccessPeopleResponse,
  type OperationalAccessPrimaryWhereKey,
  type OperationalAccessResolvedSetDto,
  type OperationalAccessResolveActor,
  type OperationalAccessRuntimePeopleResponse,
  type OperationalAccessRuntimePersonDto,
  type OperationalAccessRuntimePersonResponse,
  type OperationalAccessResponsibleForAssignmentDto,
  type OperationalAccessSourcePath,
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
  'Operational Access configuration is now consumed only by the backend resolver proof surface.',
  'People & Teams group membership remains provisioning-only by itself.',
  'Assigned Areas and broad module integrations remain deferred.',
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

function uniqueValues<T>(values: Iterable<T>): T[] {
  return [...new Set(values)];
}

function visibleFieldsFor(
  role: OperationalAccessResolveActor['role'],
  allowed: boolean,
): OperationalAccessFieldVisibility[] {
  if (!allowed) {
    return [
      { fieldKey: 'name', treatment: 'HIDDEN' },
      { fieldKey: 'email', treatment: 'HIDDEN' },
    ];
  }

  if (role === 'AGENT') {
    return [
      { fieldKey: 'name', treatment: 'VISIBLE' },
      { fieldKey: 'email', treatment: 'MASKED' },
    ];
  }

  return [
    { fieldKey: 'name', treatment: 'VISIBLE' },
    { fieldKey: 'email', treatment: 'VISIBLE' },
  ];
}

function maskRuntimePerson(
  row: OperationalAccessRuntimePersonRow,
  decision: OperationalAccessDecisionDto,
): OperationalAccessRuntimePersonDto {
  const emailTreatment = decision.fields.find((field) => field.fieldKey === 'email')?.treatment;
  const nameTreatment = decision.fields.find((field) => field.fieldKey === 'name')?.treatment;

  return {
    membershipId: row.membership_id,
    name: nameTreatment === 'VISIBLE' ? row.name : null,
    email: emailTreatment === 'VISIBLE' ? row.email : null,
    fieldVisibility: decision.fields,
    sourcePath: decision.sourcePath,
    explanation: decision.explanation,
  };
}

function parseDate(value: string): Date {
  return new Date(value);
}

function dateToIsoOrNull(value: Date | null): string | null {
  return value ? value.toISOString() : null;
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
          'Oversight, Temporary Coverage, and Special Access are available only as narrow backend resolver inputs.',
          'The only runtime consumer is the backend people/Personal Card proof surface.',
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

  async listRuntimePeople(
    actor: OperationalAccessResolveActor,
  ): Promise<OperationalAccessRuntimePeopleResponse> {
    await this.assertCapabilityEnabled(actor.tenantId);
    const actionKey: OperationalAccessActionKey = 'personal_cards.view';
    const resolvedSet = await this.resolveSet(this.deps.repo, {
      actor,
      actionKey,
      module: 'personal_cards',
      effectiveAt: new Date(),
    });

    const people = await this.deps.repo.listRuntimePeople({
      tenantId: actor.tenantId,
      membershipIds: resolvedSet.mode === 'ALL' ? 'ALL' : resolvedSet.membershipIds,
    });

    return {
      actionKey,
      module: 'personal_cards',
      people: people.map((person) => {
        const decision = this.buildAllowedDecision(
          actor.role,
          resolvedSet.sourcePath,
          resolvedSet.explanation,
        );
        return maskRuntimePerson(person, decision);
      }),
    };
  }

  async getRuntimePerson(
    actor: OperationalAccessResolveActor,
    targetMembershipId: string,
  ): Promise<OperationalAccessRuntimePersonResponse> {
    await this.assertCapabilityEnabled(actor.tenantId);
    const actionKey: OperationalAccessActionKey = 'personal_cards.view';
    const [person, decision] = await Promise.all([
      this.deps.repo.getRuntimePerson({
        tenantId: actor.tenantId,
        membershipId: targetMembershipId,
      }),
      this.resolveDecision(this.deps.repo, {
        actor,
        targetMembershipId,
        actionKey,
        effectiveAt: new Date(),
      }),
    ]);

    if (!person) throw OperationalAccessErrors.membershipNotFound(targetMembershipId);
    if (!decision.allowed) throw OperationalAccessErrors.resolverDenied();

    return {
      actionKey,
      module: 'personal_cards',
      person: maskRuntimePerson(person, decision),
      decision,
    };
  }

  async saveOversight(
    auth: OperationalAccessAuditContext,
    input: SaveOperationalAccessOversightInput,
  ): Promise<OperationalAccessAdvancedCoverageResponse> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.repo.withDb(trx);
      await this.assertCapabilityEnabled(auth.tenantId, repo);
      await this.validateOversightInput(repo, auth.tenantId, input);

      await repo.replaceOversight({
        tenantId: auth.tenantId,
        actorMembershipId: auth.membershipId,
        entries: input.entries.map((entry) => ({
          overseerMembershipId: entry.overseerMembershipId,
          targetMembershipId: entry.targetMembershipId,
          includesResponsiblePeople: entry.includesResponsiblePeople,
          reason: entry.reason,
          reviewAt: parseDate(entry.reviewAt),
        })),
      });

      await this.buildAuditWriter(trx, auth).append('operational_access.oversight_saved', {
        count: input.entries.length,
        runtimeVisibilityChanged: true,
      });

      return this.listAdvancedCoverage(auth.tenantId, repo);
    });
  }

  async saveTemporaryCoverage(
    auth: OperationalAccessAuditContext,
    input: SaveOperationalAccessTemporaryCoverageInput,
  ): Promise<OperationalAccessAdvancedCoverageResponse> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.repo.withDb(trx);
      await this.assertCapabilityEnabled(auth.tenantId, repo);
      await this.validateTemporaryCoverageInput(repo, auth.tenantId, input);

      await repo.replaceTemporaryCoverage({
        tenantId: auth.tenantId,
        actorMembershipId: auth.membershipId,
        entries: input.entries.map((entry) => ({
          coveringMembershipId: entry.coveringMembershipId,
          coveredMembershipId: entry.coveredMembershipId,
          startsAt: parseDate(entry.startsAt),
          expiresAt: parseDate(entry.expiresAt),
          reason: entry.reason,
          reviewAt: entry.reviewAt ? parseDate(entry.reviewAt) : null,
        })),
      });

      await this.buildAuditWriter(trx, auth).append('operational_access.temporary_coverage_saved', {
        count: input.entries.length,
        runtimeVisibilityChanged: true,
      });

      return this.listAdvancedCoverage(auth.tenantId, repo);
    });
  }

  async saveSpecialAccess(
    auth: OperationalAccessAuditContext,
    input: SaveOperationalAccessSpecialAccessInput,
  ): Promise<OperationalAccessAdvancedCoverageResponse> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.repo.withDb(trx);
      await this.assertCapabilityEnabled(auth.tenantId, repo);
      await this.validateSpecialAccessInput(repo, auth.tenantId, input);

      await repo.replaceSpecialAccess({
        tenantId: auth.tenantId,
        actorMembershipId: auth.membershipId,
        entries: input.entries.map((entry) => ({
          membershipId: entry.membershipId,
          targetMembershipId: entry.targetMembershipId,
          actionKey: entry.actionKey,
          reason: entry.reason,
          reviewAt: parseDate(entry.reviewAt),
          expiresAt: parseDate(entry.expiresAt),
        })),
      });

      await this.buildAuditWriter(trx, auth).append('operational_access.special_access_saved', {
        count: input.entries.length,
        runtimeVisibilityChanged: true,
      });

      return this.listAdvancedCoverage(auth.tenantId, repo);
    });
  }

  async listAdvancedCoverage(
    tenantId: string,
    repo: OperationalAccessRepo = this.deps.repo,
  ): Promise<OperationalAccessAdvancedCoverageResponse> {
    await this.assertCapabilityEnabled(tenantId, repo);
    const [oversight, temporaryCoverage, specialAccess] = await Promise.all([
      repo.listOversightConfig(tenantId),
      repo.listTemporaryCoverageConfig(tenantId),
      repo.listSpecialAccessConfig(tenantId),
    ]);

    return {
      oversight: oversight.map((entry) => ({
        overseerMembershipId: entry.overseer_membership_id,
        targetMembershipId: entry.target_membership_id,
        includesResponsiblePeople: entry.includes_responsible_people,
        reason: entry.reason,
        reviewAt: toIso(entry.review_at),
      })),
      temporaryCoverage: temporaryCoverage.map((entry) => ({
        id: entry.id,
        coveringMembershipId: entry.covering_membership_id,
        coveredMembershipId: entry.covered_membership_id,
        startsAt: toIso(entry.starts_at),
        expiresAt: toIso(entry.expires_at),
        reason: entry.reason,
        reviewAt: dateToIsoOrNull(entry.review_at),
      })),
      specialAccess: specialAccess.map((entry) => ({
        id: entry.id,
        membershipId: entry.membership_id,
        targetMembershipId: entry.target_membership_id,
        actionKey: entry.action_key as OperationalAccessActionKey,
        reason: entry.reason,
        reviewAt: toIso(entry.review_at),
        expiresAt: toIso(entry.expires_at),
      })),
    };
  }

  private async resolveSet(
    repo: OperationalAccessRepo,
    input: {
      actor: OperationalAccessResolveActor;
      actionKey: OperationalAccessActionKey;
      module: 'personal_cards';
      effectiveAt: Date;
    },
  ): Promise<OperationalAccessResolvedSetDto> {
    if (input.actor.role === 'ADMIN') {
      return {
        mode: 'ALL',
        membershipIds: [],
        sourcePath: ['ADMIN_LEVEL'],
        explanation: ['Allowed because the actor has Admin level.'],
      };
    }

    if (input.actor.role === 'USER') {
      return {
        mode: 'IDS',
        membershipIds: [input.actor.membershipId],
        sourcePath: ['USER_OWN_DATA'],
        explanation: ["Allowed only for the user's own self-service record."],
      };
    }

    return this.collectAgentSet(repo, {
      tenantId: input.actor.tenantId,
      actorMembershipId: input.actor.membershipId,
      actionKey: input.actionKey,
      effectiveAt: input.effectiveAt,
      includeAdvanced: true,
    });
  }

  private async resolveDecision(
    repo: OperationalAccessRepo,
    input: {
      actor: OperationalAccessResolveActor;
      targetMembershipId: string;
      actionKey: OperationalAccessActionKey;
      effectiveAt: Date;
    },
  ): Promise<OperationalAccessDecisionDto> {
    const resolvedSet = await this.resolveSet(repo, {
      actor: input.actor,
      actionKey: input.actionKey,
      module: 'personal_cards',
      effectiveAt: input.effectiveAt,
    });

    const allowed =
      resolvedSet.mode === 'ALL' || resolvedSet.membershipIds.includes(input.targetMembershipId);

    if (!allowed) {
      return {
        allowed: false,
        visible: false,
        editable: false,
        sourcePath: ['DENIED'],
        explanation: [
          'Denied because no backend-resolved Operational Access source matched this target.',
        ],
        fields: visibleFieldsFor(input.actor.role, false),
      };
    }

    return this.buildAllowedDecision(
      input.actor.role,
      resolvedSet.sourcePath,
      resolvedSet.explanation,
    );
  }

  private buildAllowedDecision(
    role: OperationalAccessResolveActor['role'],
    sourcePath: OperationalAccessSourcePath[],
    explanation: string[],
  ): OperationalAccessDecisionDto {
    return {
      allowed: true,
      visible: true,
      editable: false,
      sourcePath: uniqueValues(sourcePath),
      explanation: uniqueValues(explanation),
      fields: visibleFieldsFor(role, true),
    };
  }

  private async collectAgentSet(
    repo: OperationalAccessRepo,
    input: {
      tenantId: string;
      actorMembershipId: string;
      actionKey: OperationalAccessActionKey;
      effectiveAt: Date;
      includeAdvanced: boolean;
    },
  ): Promise<OperationalAccessResolvedSetDto> {
    const membershipIds = new Set<string>();
    const sourcePath: OperationalAccessSourcePath[] = [];
    const explanation: string[] = [];
    const grants = await repo.listResolverGrantsForMembership({
      tenantId: input.tenantId,
      membershipId: input.actorMembershipId,
      actionKey: input.actionKey,
    });

    for (const grant of grants) {
      if (grant.primary_where === 'TENANT_WIDE') {
        return {
          mode: 'ALL',
          membershipIds: [],
          sourcePath: ['AGENT_GROUP_TENANT_WIDE'],
          explanation: ['Allowed by an active Agent group grant for the whole tenant.'],
        };
      }

      if (grant.primary_where === 'RESPONSIBLE_FOR') {
        const targets = await repo.listResponsibleTargetIdsForAgent({
          tenantId: input.tenantId,
          groupId: grant.group_id,
          agentMembershipId: input.actorMembershipId,
        });
        for (const target of targets) membershipIds.add(target);
        if (targets.length > 0) {
          sourcePath.push('AGENT_GROUP_RESPONSIBLE_FOR');
          explanation.push('Allowed by an active Agent group grant plus Responsible For coverage.');
        }
      }
    }

    if (input.includeAdvanced) {
      await this.collectOversightTargets(repo, input, membershipIds, sourcePath, explanation);
      const tempResult = await this.collectTemporaryCoverageTargets(repo, input);
      if (tempResult.mode === 'ALL') return tempResult;
      for (const target of tempResult.membershipIds) membershipIds.add(target);
      sourcePath.push(...tempResult.sourcePath.filter((path) => path !== 'DENIED'));
      explanation.push(...tempResult.explanation);

      const specials = await repo.listActiveSpecialAccessForActor({
        tenantId: input.tenantId,
        membershipId: input.actorMembershipId,
        actionKey: input.actionKey,
        effectiveAt: input.effectiveAt,
      });
      for (const special of specials) membershipIds.add(special.target_membership_id);
      if (specials.length > 0) {
        sourcePath.push('SPECIAL_ACCESS');
        explanation.push(
          'Allowed by active Special Access with reason, review date, and expiry metadata.',
        );
      }
    }

    return {
      mode: 'IDS',
      membershipIds: [...membershipIds],
      sourcePath: sourcePath.length > 0 ? uniqueValues(sourcePath) : ['DENIED'],
      explanation:
        explanation.length > 0
          ? uniqueValues(explanation)
          : ['No active grant and matching coverage key resolved for this actor.'],
    };
  }

  private async collectOversightTargets(
    repo: OperationalAccessRepo,
    input: {
      tenantId: string;
      actorMembershipId: string;
      actionKey: OperationalAccessActionKey;
      effectiveAt: Date;
    },
    membershipIds: Set<string>,
    sourcePath: OperationalAccessSourcePath[],
    explanation: string[],
  ): Promise<void> {
    const oversightRows = await repo.listOversightForActor({
      tenantId: input.tenantId,
      membershipId: input.actorMembershipId,
    });

    for (const oversight of oversightRows) {
      membershipIds.add(oversight.target_membership_id);
      sourcePath.push('OVERSIGHT_DIRECT');
      explanation.push(
        'Allowed to see the overseen person because Oversight is directed to that person.',
      );

      if (oversight.includes_responsible_people) {
        const overseenSet = await this.collectAgentSet(repo, {
          tenantId: input.tenantId,
          actorMembershipId: oversight.target_membership_id,
          actionKey: input.actionKey,
          effectiveAt: input.effectiveAt,
          includeAdvanced: false,
        });
        for (const target of overseenSet.membershipIds) membershipIds.add(target);
        if (overseenSet.membershipIds.length > 0 || overseenSet.mode === 'ALL') {
          sourcePath.push('OVERSIGHT_RESPONSIBLE_PEOPLE');
          explanation.push(
            'Allowed through Oversight because includes responsible people/work is explicitly enabled.',
          );
        }
      }
    }
  }

  private async collectTemporaryCoverageTargets(
    repo: OperationalAccessRepo,
    input: {
      tenantId: string;
      actorMembershipId: string;
      actionKey: OperationalAccessActionKey;
      effectiveAt: Date;
    },
  ): Promise<OperationalAccessResolvedSetDto> {
    const rows = await repo.listActiveTemporaryCoverageForActor({
      tenantId: input.tenantId,
      membershipId: input.actorMembershipId,
      effectiveAt: input.effectiveAt,
    });

    const membershipIds = new Set<string>();
    const sourcePath: OperationalAccessSourcePath[] = [];
    const explanation: string[] = [];

    for (const row of rows) {
      membershipIds.add(row.covered_membership_id);
      const coveredSet = await this.collectAgentSet(repo, {
        tenantId: input.tenantId,
        actorMembershipId: row.covered_membership_id,
        actionKey: input.actionKey,
        effectiveAt: input.effectiveAt,
        includeAdvanced: false,
      });

      if (coveredSet.mode === 'ALL') {
        return {
          mode: 'ALL',
          membershipIds: [],
          sourcePath: ['TEMPORARY_COVERAGE'],
          explanation: ["Allowed by active Temporary Coverage copying the covered person's keys."],
        };
      }

      for (const target of coveredSet.membershipIds) membershipIds.add(target);
      sourcePath.push('TEMPORARY_COVERAGE');
      explanation.push('Allowed by active Temporary Coverage within its start/end window.');
    }

    return {
      mode: 'IDS',
      membershipIds: [...membershipIds],
      sourcePath: uniqueValues(sourcePath),
      explanation: uniqueValues(explanation),
    };
  }

  private async validateOversightInput(
    repo: OperationalAccessRepo,
    tenantId: string,
    input: SaveOperationalAccessOversightInput,
  ): Promise<void> {
    const seen = new Set<string>();

    for (const entry of input.entries) {
      const key = `${entry.overseerMembershipId}:${entry.targetMembershipId}`;
      if (seen.has(key)) throw OperationalAccessErrors.duplicateAdvancedCoverage('oversight');
      seen.add(key);
      await this.assertActiveAgentMembership(repo, tenantId, entry.overseerMembershipId);
      await this.assertActiveAgentMembership(repo, tenantId, entry.targetMembershipId);
      if (entry.overseerMembershipId === entry.targetMembershipId) {
        throw OperationalAccessErrors.selfResponsibleForNotAllowed(entry.overseerMembershipId);
      }
    }
  }

  private async validateTemporaryCoverageInput(
    repo: OperationalAccessRepo,
    tenantId: string,
    input: SaveOperationalAccessTemporaryCoverageInput,
  ): Promise<void> {
    const seen = new Set<string>();

    for (const entry of input.entries) {
      const startsAt = parseDate(entry.startsAt);
      const expiresAt = parseDate(entry.expiresAt);
      if (startsAt >= expiresAt) throw OperationalAccessErrors.invalidTimeWindow();
      if (entry.reviewAt && parseDate(entry.reviewAt) > expiresAt) {
        throw OperationalAccessErrors.reviewMustNotBeAfterExpiry();
      }

      const key = `${entry.coveringMembershipId}:${entry.coveredMembershipId}:${entry.startsAt}:${entry.expiresAt}`;
      if (seen.has(key))
        throw OperationalAccessErrors.duplicateAdvancedCoverage('temporary_coverage');
      seen.add(key);
      await this.assertActiveAgentMembership(repo, tenantId, entry.coveringMembershipId);
      await this.assertActiveAgentMembership(repo, tenantId, entry.coveredMembershipId);
      if (entry.coveringMembershipId === entry.coveredMembershipId) {
        throw OperationalAccessErrors.selfResponsibleForNotAllowed(entry.coveringMembershipId);
      }
    }
  }

  private async validateSpecialAccessInput(
    repo: OperationalAccessRepo,
    tenantId: string,
    input: SaveOperationalAccessSpecialAccessInput,
  ): Promise<void> {
    const now = new Date();
    const seen = new Set<string>();

    for (const entry of input.entries) {
      const reviewAt = parseDate(entry.reviewAt);
      const expiresAt = parseDate(entry.expiresAt);
      if (expiresAt <= now) throw OperationalAccessErrors.expiryRequiredInFuture();
      if (reviewAt > expiresAt) throw OperationalAccessErrors.reviewMustNotBeAfterExpiry();

      const key = `${entry.membershipId}:${entry.targetMembershipId}:${entry.actionKey}`;
      if (seen.has(key)) throw OperationalAccessErrors.duplicateAdvancedCoverage('special_access');
      seen.add(key);
      await this.assertActiveAgentMembership(repo, tenantId, entry.membershipId);
      await this.assertActiveTenantMembership(repo, tenantId, entry.targetMembershipId);
      if (entry.membershipId === entry.targetMembershipId) {
        throw OperationalAccessErrors.selfResponsibleForNotAllowed(entry.membershipId);
      }
    }
  }

  private async assertActiveAgentMembership(
    repo: OperationalAccessRepo,
    tenantId: string,
    membershipId: string,
  ): Promise<void> {
    const membership = await repo.getActiveMembership({ tenantId, membershipId });
    if (!membership) throw OperationalAccessErrors.membershipNotFound(membershipId);
    if (requireMembershipRole(membership.role) !== 'AGENT') {
      throw OperationalAccessErrors.agentMembershipRequired(membershipId);
    }
  }

  private async assertActiveTenantMembership(
    repo: OperationalAccessRepo,
    tenantId: string,
    membershipId: string,
  ): Promise<void> {
    const membership = await repo.getActiveMembership({ tenantId, membershipId });
    if (!membership) throw OperationalAccessErrors.membershipNotFound(membershipId);
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
        runtimeVisibilityChanged: true,
        effectiveAccessResolverShipped: true,
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
