/**
 * backend/src/modules/operational-access/dal/operational-access.repo.ts
 *
 * WHY:
 * - Repository wrapper for Operational Access configuration and resolver proof reads/writes.
 * - Keeps service logic free from raw Kysely query construction.
 *
 * RULES:
 * - No transactions started here.
 * - No AppError.
 * - Resolver methods return tenant-scoped data only; services own allow/deny decisions.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type {
  OperationalAccessActionKey,
  OperationalAccessPrimaryWhereKey,
  OperationalAccessWhichRecordsKey,
} from '../operational-access.types';
import {
  assertAdvancedCoverageVersionSql,
  bumpAdvancedCoverageVersionSql,
  insertOversightRowsSql,
  insertSpecialAccessRowsSql,
  insertTemporaryCoverageRowsSql,
  replaceGroupGrantsSql,
  replaceResponsibleForAssignmentsSql,
  selectAdvancedCoverageVersionSql,
  selectActiveAgentGroupsSql,
  selectActiveGroupMemberSql,
  selectActiveMembershipSql,
  selectActivePeopleSql,
  selectActiveSpecialAccessRowsForActorSql,
  selectActiveTemporaryCoverageRowsForActorSql,
  selectGroupGrantsSql,
  selectOperationalAccessGroupSql,
  selectOperationalAccessTenantCapabilitySql,
  selectOversightConfigSql,
  selectOversightRowsForActorSql,
  selectResolverGrantsForMembershipSql,
  selectResponsibleForAssignmentsSql,
  selectResponsibleForTargetIdsForAgentSql,
  selectRuntimePeopleSql,
  selectRuntimePersonByMembershipIdSql,
  selectSpecialAccessConfigSql,
  selectStoredOperationalAccessGroupSql,
  selectTemporaryCoverageConfigSql,
  type OperationalAccessGrantRow,
  type OperationalAccessGroupRow,
  type OperationalAccessMembershipRow,
  type OperationalAccessOversightRow,
  type OperationalAccessResolverGrantRow,
  type OperationalAccessResponsibleForRow,
  type OperationalAccessRuntimePersonRow,
  type OperationalAccessSpecialAccessRow,
  type OperationalAccessStoredGroupRow,
  type OperationalAccessTemporaryCoverageRow,
  type OperationalAccessTenantCapabilityRow,
} from './operational-access.query-sql';

export class OperationalAccessRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): OperationalAccessRepo {
    return new OperationalAccessRepo(db);
  }

  getTenantCapability(tenantId: string): Promise<OperationalAccessTenantCapabilityRow | undefined> {
    return selectOperationalAccessTenantCapabilitySql(this.db, tenantId);
  }

  getAdvancedCoverageVersion(tenantId: string): Promise<number> {
    return selectAdvancedCoverageVersionSql(this.db, tenantId);
  }

  advancedCoverageVersionMatches(input: {
    tenantId: string;
    expectedVersion: number;
  }): Promise<boolean> {
    return assertAdvancedCoverageVersionSql(this.db, input);
  }

  bumpAdvancedCoverageVersion(input: {
    tenantId: string;
    actorMembershipId: string;
  }): Promise<number> {
    return bumpAdvancedCoverageVersionSql(this.db, input);
  }

  listActiveAgentGroups(tenantId: string): Promise<OperationalAccessGroupRow[]> {
    return selectActiveAgentGroupsSql(this.db, tenantId);
  }

  getGroup(input: {
    tenantId: string;
    groupId: string;
  }): Promise<OperationalAccessGroupRow | undefined> {
    return selectOperationalAccessGroupSql(this.db, input);
  }

  getStoredGroup(input: {
    tenantId: string;
    groupId: string;
  }): Promise<OperationalAccessStoredGroupRow | undefined> {
    return selectStoredOperationalAccessGroupSql(this.db, input);
  }

  listGroupGrants(input: {
    tenantId: string;
    groupId: string;
  }): Promise<OperationalAccessGrantRow[]> {
    return selectGroupGrantsSql(this.db, input);
  }

  replaceGroupGrants(input: {
    tenantId: string;
    groupId: string;
    actorMembershipId: string;
    grants: Array<{
      actionKey: OperationalAccessActionKey;
      primaryWhere: OperationalAccessPrimaryWhereKey;
      whichRecordsKey: OperationalAccessWhichRecordsKey;
    }>;
  }): Promise<void> {
    return replaceGroupGrantsSql(this.db, input);
  }

  getActiveMembership(input: {
    tenantId: string;
    membershipId: string;
  }): Promise<OperationalAccessMembershipRow | undefined> {
    return selectActiveMembershipSql(this.db, input);
  }

  listActivePeople(tenantId: string): Promise<OperationalAccessMembershipRow[]> {
    return selectActivePeopleSql(this.db, tenantId);
  }

  getActiveGroupMember(input: {
    tenantId: string;
    groupId: string;
    membershipId: string;
  }): Promise<{ membership_id: string } | undefined> {
    return selectActiveGroupMemberSql(this.db, input);
  }

  listResponsibleFor(input: {
    tenantId: string;
    groupId: string;
  }): Promise<OperationalAccessResponsibleForRow[]> {
    return selectResponsibleForAssignmentsSql(this.db, input);
  }

  replaceResponsibleFor(input: {
    tenantId: string;
    groupId: string;
    actorMembershipId: string;
    assignments: Array<{ agentMembershipId: string; targetMembershipId: string }>;
  }): Promise<void> {
    return replaceResponsibleForAssignmentsSql(this.db, input);
  }

  listResolverGrantsForMembership(input: {
    tenantId: string;
    membershipId: string;
    actionKey: OperationalAccessActionKey;
  }): Promise<OperationalAccessResolverGrantRow[]> {
    return selectResolverGrantsForMembershipSql(this.db, input);
  }

  listResponsibleTargetIdsForAgent(input: {
    tenantId: string;
    groupId: string;
    agentMembershipId: string;
  }): Promise<string[]> {
    return selectResponsibleForTargetIdsForAgentSql(this.db, input);
  }

  listOversightForActor(input: {
    tenantId: string;
    membershipId: string;
  }): Promise<OperationalAccessOversightRow[]> {
    return selectOversightRowsForActorSql(this.db, input);
  }

  listActiveTemporaryCoverageForActor(input: {
    tenantId: string;
    membershipId: string;
    effectiveAt: Date;
  }): Promise<OperationalAccessTemporaryCoverageRow[]> {
    return selectActiveTemporaryCoverageRowsForActorSql(this.db, input);
  }

  listActiveSpecialAccessForActor(input: {
    tenantId: string;
    membershipId: string;
    actionKey: OperationalAccessActionKey;
    effectiveAt: Date;
  }): Promise<OperationalAccessSpecialAccessRow[]> {
    return selectActiveSpecialAccessRowsForActorSql(this.db, input);
  }

  listRuntimePeople(input: {
    tenantId: string;
    membershipIds: string[] | 'ALL';
  }): Promise<OperationalAccessRuntimePersonRow[]> {
    return selectRuntimePeopleSql(this.db, input);
  }

  getRuntimePerson(input: {
    tenantId: string;
    membershipId: string;
  }): Promise<OperationalAccessRuntimePersonRow | undefined> {
    return selectRuntimePersonByMembershipIdSql(this.db, input);
  }

  replaceOversight(input: {
    tenantId: string;
    actorMembershipId: string;
    replaceForMembershipIds: string[];
    entries: Array<{
      overseerMembershipId: string;
      targetMembershipId: string;
      includesResponsiblePeople: boolean;
      reason: string;
      reviewAt: Date;
    }>;
  }): Promise<void> {
    return insertOversightRowsSql(this.db, input);
  }

  replaceTemporaryCoverage(input: {
    tenantId: string;
    actorMembershipId: string;
    replaceForMembershipIds: string[];
    entries: Array<{
      coveringMembershipId: string;
      coveredMembershipId: string;
      startsAt: Date;
      expiresAt: Date;
      reason: string;
      reviewAt: Date | null;
    }>;
  }): Promise<void> {
    return insertTemporaryCoverageRowsSql(this.db, input);
  }

  replaceSpecialAccess(input: {
    tenantId: string;
    actorMembershipId: string;
    replaceForMembershipIds: string[];
    entries: Array<{
      membershipId: string;
      targetMembershipId: string;
      actionKey: OperationalAccessActionKey;
      reason: string;
      reviewAt: Date;
      expiresAt: Date;
    }>;
  }): Promise<void> {
    return insertSpecialAccessRowsSql(this.db, input);
  }

  listOversightConfig(tenantId: string): Promise<OperationalAccessOversightRow[]> {
    return selectOversightConfigSql(this.db, tenantId);
  }

  listTemporaryCoverageConfig(tenantId: string): Promise<OperationalAccessTemporaryCoverageRow[]> {
    return selectTemporaryCoverageConfigSql(this.db, tenantId);
  }

  listSpecialAccessConfig(tenantId: string): Promise<OperationalAccessSpecialAccessRow[]> {
    return selectSpecialAccessConfigSql(this.db, tenantId);
  }
}
