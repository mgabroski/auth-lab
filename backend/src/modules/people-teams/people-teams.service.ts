/**
 * backend/src/modules/people-teams/people-teams.service.ts
 *
 * WHY:
 * - Read-only application service for the People & Teams foundation.
 * - Shapes tenant-scoped repo rows into backend-owned DTO contracts.
 *
 * RULES:
 * - No Operational Access grants, scopes, Person Exceptions, or resolver work.
 * - Group level is classification only and does not affect runtime auth roles.
 */

import type { MembershipRole, MembershipStatus } from '../memberships/membership.types';
import type {
  PeopleTeamGroupDto,
  PeopleTeamGroupLevel,
  PeopleTeamGroupsResponse,
  PeopleTeamGroupStatus,
  PeopleTeamPeopleResponse,
  PeopleTeamPersonDto,
} from './people-teams.types';
import type { PeopleTeamsRepo } from './dal/people-teams.repo';
import type { PeopleTeamGroupRow, PeopleTeamPersonRow } from './dal/people-teams.query-sql';

function toIso(value: Date | null): string | null {
  return value ? value.toISOString() : null;
}

function parseCount(value: string | number | bigint): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'bigint') return Number(value);
  return Number.parseInt(value, 10);
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

function rowToPersonDto(row: PeopleTeamPersonRow): PeopleTeamPersonDto {
  return {
    membershipId: row.membership_id,
    userId: row.user_id,
    email: row.email,
    name: row.name,
    role: row.role as MembershipRole,
    status: row.status as Extract<MembershipStatus, 'ACTIVE'>,
  };
}

export class PeopleTeamsService {
  constructor(private readonly repo: PeopleTeamsRepo) {}

  async listGroups(tenantId: string): Promise<PeopleTeamGroupsResponse> {
    const rows = await this.repo.listActiveGroups(tenantId);
    return { groups: rows.map(rowToGroupDto) };
  }

  async listPeople(tenantId: string): Promise<PeopleTeamPeopleResponse> {
    const rows = await this.repo.listActivePeople(tenantId);
    return { people: rows.map(rowToPersonDto) };
  }
}
