/**
 * backend/src/modules/operational-access/dal/operational-access.repo.ts
 *
 * WHY:
 * - Repository wrapper for Operational Access Step 3 configuration reads/writes.
 * - Keeps service logic free from raw Kysely query construction.
 *
 * RULES:
 * - No transactions started here.
 * - No AppError.
 * - No Effective Access Resolver methods.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type {
  OperationalAccessActionKey,
  OperationalAccessPrimaryWhereKey,
  OperationalAccessWhichRecordsKey,
} from '../operational-access.types';
import {
  replaceGroupGrantsSql,
  replaceResponsibleForAssignmentsSql,
  selectActiveAgentGroupsSql,
  selectActiveGroupMemberSql,
  selectActiveMembershipSql,
  selectActivePeopleSql,
  selectGroupGrantsSql,
  selectOperationalAccessGroupSql,
  selectOperationalAccessTenantCapabilitySql,
  selectResponsibleForAssignmentsSql,
  selectStoredOperationalAccessGroupSql,
  type OperationalAccessGrantRow,
  type OperationalAccessGroupRow,
  type OperationalAccessMembershipRow,
  type OperationalAccessResponsibleForRow,
  type OperationalAccessStoredGroupRow,
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
}
