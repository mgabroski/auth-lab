/**
 * backend/src/modules/people-teams/dal/people-teams.repo.ts
 *
 * WHY:
 * - Repository wrapper for People & Teams reads and group lifecycle writes.
 * - Keeps service code independent from raw query construction.
 *
 * RULES:
 * - No transactions started here.
 * - No AppError.
 * - No Operational Access grant methods.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { PeopleTeamGroupLevel } from '../people-teams.types';
import {
  archiveActiveGroupSql,
  deleteGroupMemberSql,
  insertGroupMemberSql,
  insertGroupSql,
  selectActiveGroupsByTenantSql,
  selectActivePeopleByTenantSql,
  selectGroupByIdForTenantSql,
  selectExistingGroupMemberSql,
  selectGroupByNormalizedNameSql,
  selectGroupMemberSql,
  selectGroupMembersSql,
  selectMembershipByTenantSql,
  selectStoredGroupByIdForTenantSql,
  updateActiveGroupSql,
  type PeopleTeamGroupMemberRow,
  type PeopleTeamGroupRow,
  type PeopleTeamMembershipRow,
  type PeopleTeamPersonRow,
  type PeopleTeamStoredGroupRow,
} from './people-teams.query-sql';

export class PeopleTeamsRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): PeopleTeamsRepo {
    return new PeopleTeamsRepo(db);
  }

  listActiveGroups(tenantId: string): Promise<PeopleTeamGroupRow[]> {
    return selectActiveGroupsByTenantSql(this.db, tenantId);
  }

  getGroup(tenantId: string, groupId: string): Promise<PeopleTeamGroupRow | undefined> {
    return selectGroupByIdForTenantSql(this.db, tenantId, groupId);
  }

  getStoredGroup(tenantId: string, groupId: string): Promise<PeopleTeamStoredGroupRow | undefined> {
    return selectStoredGroupByIdForTenantSql(this.db, tenantId, groupId);
  }

  findByNormalizedName(
    tenantId: string,
    normalizedName: string,
  ): Promise<{ id: string } | undefined> {
    return selectGroupByNormalizedNameSql(this.db, tenantId, normalizedName);
  }

  createGroup(input: {
    tenantId: string;
    name: string;
    normalizedName: string;
    description: string | null;
    level: PeopleTeamGroupLevel;
    actorMembershipId: string;
  }): Promise<PeopleTeamStoredGroupRow> {
    return insertGroupSql(this.db, input);
  }

  updateActiveGroup(input: {
    tenantId: string;
    groupId: string;
    name: string;
    normalizedName: string;
    description: string | null;
    level: PeopleTeamGroupLevel;
    actorMembershipId: string;
  }): Promise<PeopleTeamStoredGroupRow | undefined> {
    return updateActiveGroupSql(this.db, input);
  }

  archiveActiveGroup(input: {
    tenantId: string;
    groupId: string;
    actorMembershipId: string;
  }): Promise<PeopleTeamStoredGroupRow | undefined> {
    return archiveActiveGroupSql(this.db, input);
  }

  listGroupMembers(input: {
    tenantId: string;
    groupId: string;
  }): Promise<PeopleTeamGroupMemberRow[]> {
    return selectGroupMembersSql(this.db, input);
  }

  getGroupMember(input: {
    tenantId: string;
    groupId: string;
    membershipId: string;
  }): Promise<PeopleTeamGroupMemberRow | undefined> {
    return selectGroupMemberSql(this.db, input);
  }

  getMembership(input: {
    tenantId: string;
    membershipId: string;
  }): Promise<PeopleTeamMembershipRow | undefined> {
    return selectMembershipByTenantSql(this.db, input);
  }

  findExistingGroupMember(input: {
    tenantId: string;
    groupId: string;
    membershipId: string;
  }): Promise<{ membership_id: string } | undefined> {
    return selectExistingGroupMemberSql(this.db, input);
  }

  async addGroupMember(input: {
    tenantId: string;
    groupId: string;
    membershipId: string;
    actorMembershipId: string;
  }): Promise<void> {
    await insertGroupMemberSql(this.db, input);
  }

  removeGroupMember(input: {
    tenantId: string;
    groupId: string;
    membershipId: string;
  }): Promise<{ membership_id: string } | undefined> {
    return deleteGroupMemberSql(this.db, input);
  }

  listActivePeople(tenantId: string): Promise<PeopleTeamPersonRow[]> {
    return selectActivePeopleByTenantSql(this.db, tenantId);
  }
}
