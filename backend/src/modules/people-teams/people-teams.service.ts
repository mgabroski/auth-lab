/**
 * backend/src/modules/people-teams/people-teams.service.ts
 *
 * WHY:
 * - Application service for the People & Teams foundation.
 * - Shapes tenant-scoped repo rows into backend-owned DTO contracts and owns
 *   group lifecycle write transactions.
 *
 * RULES:
 * - No Operational Access grants, scopes, Person Exceptions, or resolver work.
 * - Group level is classification only and does not mutate runtime membership roles.
 */

import type { AuditRepo } from '../../shared/audit/audit.repo';
import { AuditWriter } from '../../shared/audit/audit.writer';
import type { DbExecutor } from '../../shared/db/db';
import type { MembershipStatus } from '../memberships/membership.types';
import { requireMembershipRole } from '../memberships';
import {
  auditPeopleTeamGroupArchived,
  auditPeopleTeamGroupCreated,
  auditPeopleTeamGroupUpdated,
  auditPeopleTeamMemberAdded,
  auditPeopleTeamMemberRemoved,
} from './people-teams.audit';
import type {
  CreatePeopleTeamGroupInput,
  UpdatePeopleTeamGroupInput,
} from './people-teams.schemas';
import type {
  PeopleTeamAuditContext,
  PeopleTeamGroupDto,
  PeopleTeamGroupLevel,
  PeopleTeamGroupMemberDto,
  PeopleTeamGroupMemberResponse,
  PeopleTeamGroupMembersResponse,
  PeopleTeamGroupResponse,
  PeopleTeamGroupsResponse,
  PeopleTeamGroupStatus,
  PeopleTeamPeopleResponse,
  PeopleTeamPersonDto,
} from './people-teams.types';
import type { PeopleTeamsRepo } from './dal/people-teams.repo';
import type {
  PeopleTeamGroupMemberRow,
  PeopleTeamGroupRow,
  PeopleTeamMembershipRow,
  PeopleTeamPersonRow,
  PeopleTeamStoredGroupRow,
} from './dal/people-teams.query-sql';
import { PeopleTeamsErrors } from './people-teams.errors';

function toIso(value: Date | null): string | null {
  return value ? value.toISOString() : null;
}

function parseCount(value: string | number | bigint): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'bigint') return Number(value);
  return Number.parseInt(value, 10);
}

const GROUP_NORMALIZED_NAME_UNIQUE_CONSTRAINT = 'tenant_groups_tenant_normalized_name_unique';

function normalizeGroupName(name: string): string {
  return name.trim().replace(/\s+/g, ' ').toLowerCase();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function getErrorStringField(error: unknown, fieldName: string): string | undefined {
  if (isRecord(error) && typeof error[fieldName] === 'string') {
    return error[fieldName];
  }

  if (isRecord(error) && isRecord(error.cause) && typeof error.cause[fieldName] === 'string') {
    return error.cause[fieldName];
  }

  return undefined;
}

function isPgUniqueConstraintViolation(error: unknown, constraintName: string): boolean {
  return (
    getErrorStringField(error, 'code') === '23505' &&
    getErrorStringField(error, 'constraint') === constraintName
  );
}

function rowToGroupDto(row: PeopleTeamGroupRow): PeopleTeamGroupDto {
  return {
    id: row.id,
    name: row.name,
    normalizedName: row.normalized_name,
    description: row.description,
    level: row.level as PeopleTeamGroupLevel,
    status: row.status as PeopleTeamGroupStatus,
    memberCount: parseCount(row.member_count),
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
    archivedAt: toIso(row.archived_at),
  };
}

function storedGroupToAuditSummary(row: PeopleTeamStoredGroupRow) {
  return {
    id: row.id,
    name: row.name,
    normalizedName: row.normalized_name,
    description: row.description,
    level: row.level as PeopleTeamGroupLevel,
    status: row.status,
  };
}

function rowToPersonDto(row: PeopleTeamPersonRow): PeopleTeamPersonDto {
  return {
    membershipId: row.membership_id,
    userId: row.user_id,
    email: row.email,
    name: row.name,
    role: requireMembershipRole(row.role),
    status: row.status as Extract<MembershipStatus, 'ACTIVE'>,
  };
}

function rowToGroupMemberDto(row: PeopleTeamGroupMemberRow): PeopleTeamGroupMemberDto {
  return {
    membershipId: row.membership_id,
    userId: row.user_id,
    email: row.email,
    name: row.name,
    role: requireMembershipRole(row.role),
    status: row.status as MembershipStatus,
    addedAt: row.created_at.toISOString(),
  };
}

function membershipToAuditSummary(groupId: string, row: PeopleTeamMembershipRow) {
  return {
    groupId,
    membershipId: row.membership_id,
    userId: row.user_id,
    email: row.email,
    name: row.name,
    role: requireMembershipRole(row.role),
    status: row.status as MembershipStatus,
  };
}

export class PeopleTeamsService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      auditRepo: AuditRepo;
      repo: PeopleTeamsRepo;
    },
  ) {}

  async listGroups(tenantId: string): Promise<PeopleTeamGroupsResponse> {
    const rows = await this.deps.repo.listActiveGroups(tenantId);
    return { groups: rows.map(rowToGroupDto) };
  }

  async getGroup(tenantId: string, groupId: string): Promise<PeopleTeamGroupResponse> {
    const row = await this.deps.repo.getGroup(tenantId, groupId);
    if (!row) throw PeopleTeamsErrors.groupNotFound(groupId);
    return { group: rowToGroupDto(row) };
  }

  async listPeople(tenantId: string): Promise<PeopleTeamPeopleResponse> {
    const rows = await this.deps.repo.listActivePeople(tenantId);
    return { people: rows.map(rowToPersonDto) };
  }

  async listGroupMembers(
    tenantId: string,
    groupId: string,
  ): Promise<PeopleTeamGroupMembersResponse> {
    const group = await this.deps.repo.getStoredGroup(tenantId, groupId);
    if (!group) throw PeopleTeamsErrors.groupNotFound(groupId);

    const rows = await this.deps.repo.listGroupMembers({ tenantId, groupId });
    return { members: rows.map(rowToGroupMemberDto) };
  }

  async addGroupMember(
    auth: PeopleTeamAuditContext,
    groupId: string,
    membershipId: string,
  ): Promise<PeopleTeamGroupMemberResponse> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.repo.withDb(trx);
      const group = await repo.getStoredGroup(auth.tenantId, groupId);

      if (!group) throw PeopleTeamsErrors.groupNotFound(groupId);
      if (group.status === 'ARCHIVED') throw PeopleTeamsErrors.archivedGroupReadOnly(groupId);

      const membership = await repo.getMembership({ tenantId: auth.tenantId, membershipId });
      if (!membership) throw PeopleTeamsErrors.membershipNotFound(membershipId);
      if (membership.status !== 'ACTIVE') throw PeopleTeamsErrors.inactiveMembership(membershipId);

      const existing = await repo.findExistingGroupMember({
        tenantId: auth.tenantId,
        groupId,
        membershipId,
      });
      if (existing) throw PeopleTeamsErrors.duplicateGroupMember(groupId, membershipId);

      await repo.addGroupMember({
        tenantId: auth.tenantId,
        groupId,
        membershipId,
        actorMembershipId: auth.membershipId,
      });

      const writer = this.buildAuditWriter(trx, auth);
      await auditPeopleTeamMemberAdded(writer, {
        member: membershipToAuditSummary(groupId, membership),
        source: 'PeopleTeamsService.addGroupMember',
      });

      const added = await repo.getGroupMember({ tenantId: auth.tenantId, groupId, membershipId });
      if (!added) throw PeopleTeamsErrors.groupMemberNotFound(groupId, membershipId);
      return { member: rowToGroupMemberDto(added) };
    });
  }

  async removeGroupMember(
    auth: PeopleTeamAuditContext,
    groupId: string,
    membershipId: string,
  ): Promise<PeopleTeamGroupMemberResponse> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.repo.withDb(trx);
      const group = await repo.getStoredGroup(auth.tenantId, groupId);

      if (!group) throw PeopleTeamsErrors.groupNotFound(groupId);
      if (group.status === 'ARCHIVED') throw PeopleTeamsErrors.archivedGroupReadOnly(groupId);

      const membership = await repo.getMembership({ tenantId: auth.tenantId, membershipId });
      if (!membership) throw PeopleTeamsErrors.membershipNotFound(membershipId);

      const existing = await repo.getGroupMember({
        tenantId: auth.tenantId,
        groupId,
        membershipId,
      });
      if (!existing) throw PeopleTeamsErrors.groupMemberNotFound(groupId, membershipId);

      const removed = await repo.removeGroupMember({
        tenantId: auth.tenantId,
        groupId,
        membershipId,
      });
      if (!removed) throw PeopleTeamsErrors.groupMemberNotFound(groupId, membershipId);

      const writer = this.buildAuditWriter(trx, auth);
      await auditPeopleTeamMemberRemoved(writer, {
        member: membershipToAuditSummary(groupId, membership),
        source: 'PeopleTeamsService.removeGroupMember',
      });

      return { member: rowToGroupMemberDto(existing) };
    });
  }

  async createGroup(
    auth: PeopleTeamAuditContext,
    input: CreatePeopleTeamGroupInput,
  ): Promise<PeopleTeamGroupResponse> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.repo.withDb(trx);
      const normalizedName = normalizeGroupName(input.name);
      await this.assertGroupNameAvailable(repo, auth.tenantId, normalizedName);

      let created: PeopleTeamStoredGroupRow;
      try {
        created = await repo.createGroup({
          tenantId: auth.tenantId,
          name: input.name,
          normalizedName,
          description: input.description,
          level: input.level,
          actorMembershipId: auth.membershipId,
        });
      } catch (error: unknown) {
        if (isPgUniqueConstraintViolation(error, GROUP_NORMALIZED_NAME_UNIQUE_CONSTRAINT)) {
          throw PeopleTeamsErrors.duplicateGroupName(normalizedName);
        }

        throw error;
      }

      const writer = this.buildAuditWriter(trx, auth);
      await auditPeopleTeamGroupCreated(writer, {
        group: storedGroupToAuditSummary(created),
        source: 'PeopleTeamsService.createGroup',
      });

      const group = await repo.getGroup(auth.tenantId, created.id);
      if (!group) throw PeopleTeamsErrors.groupNotFound(created.id);
      return { group: rowToGroupDto(group) };
    });
  }

  async updateGroup(
    auth: PeopleTeamAuditContext,
    groupId: string,
    input: UpdatePeopleTeamGroupInput,
  ): Promise<PeopleTeamGroupResponse> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.repo.withDb(trx);
      const existing = await repo.getStoredGroup(auth.tenantId, groupId);

      if (!existing) throw PeopleTeamsErrors.groupNotFound(groupId);
      if (existing.status === 'ARCHIVED') throw PeopleTeamsErrors.archivedGroupReadOnly(groupId);

      const normalizedName = normalizeGroupName(input.name);
      await this.assertGroupNameAvailable(repo, auth.tenantId, normalizedName, groupId);

      let updated: PeopleTeamStoredGroupRow | undefined;
      try {
        updated = await repo.updateActiveGroup({
          tenantId: auth.tenantId,
          groupId,
          name: input.name,
          normalizedName,
          description: input.description,
          level: input.level,
          actorMembershipId: auth.membershipId,
        });
      } catch (error: unknown) {
        if (isPgUniqueConstraintViolation(error, GROUP_NORMALIZED_NAME_UNIQUE_CONSTRAINT)) {
          throw PeopleTeamsErrors.duplicateGroupName(normalizedName);
        }

        throw error;
      }

      if (!updated) throw PeopleTeamsErrors.groupNotFound(groupId);

      const writer = this.buildAuditWriter(trx, auth);
      await auditPeopleTeamGroupUpdated(writer, {
        before: storedGroupToAuditSummary(existing),
        after: storedGroupToAuditSummary(updated),
        source: 'PeopleTeamsService.updateGroup',
      });

      const group = await repo.getGroup(auth.tenantId, groupId);
      if (!group) throw PeopleTeamsErrors.groupNotFound(groupId);
      return { group: rowToGroupDto(group) };
    });
  }

  async archiveGroup(
    auth: PeopleTeamAuditContext,
    groupId: string,
  ): Promise<PeopleTeamGroupResponse> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.repo.withDb(trx);
      const existing = await repo.getStoredGroup(auth.tenantId, groupId);

      if (!existing) throw PeopleTeamsErrors.groupNotFound(groupId);
      if (existing.status === 'ARCHIVED') throw PeopleTeamsErrors.archivedGroupReadOnly(groupId);

      const archived = await repo.archiveActiveGroup({
        tenantId: auth.tenantId,
        groupId,
        actorMembershipId: auth.membershipId,
      });

      if (!archived) throw PeopleTeamsErrors.groupNotFound(groupId);

      const writer = this.buildAuditWriter(trx, auth);
      await auditPeopleTeamGroupArchived(writer, {
        before: storedGroupToAuditSummary(existing),
        after: storedGroupToAuditSummary(archived),
        source: 'PeopleTeamsService.archiveGroup',
      });

      const group = await repo.getGroup(auth.tenantId, groupId);
      if (!group) throw PeopleTeamsErrors.groupNotFound(groupId);
      return { group: rowToGroupDto(group) };
    });
  }

  private async assertGroupNameAvailable(
    repo: PeopleTeamsRepo,
    tenantId: string,
    normalizedName: string,
    currentGroupId?: string,
  ): Promise<void> {
    const duplicate = await repo.findByNormalizedName(tenantId, normalizedName);

    if (duplicate && duplicate.id !== currentGroupId) {
      throw PeopleTeamsErrors.duplicateGroupName(normalizedName);
    }
  }

  private buildAuditWriter(db: DbExecutor, context: PeopleTeamAuditContext): AuditWriter {
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
