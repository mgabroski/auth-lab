/**
 * frontend/src/shared/operational-access/contracts.ts
 *
 * WHY:
 * - Mirrors backend-owned Operational Access Step 3 DTOs for the admin settings shell.
 * - Keeps frontend rendering grounded in product-defined actions, Primary Where,
 *   Which Records, and Responsible For coverage data.
 *
 * RULES:
 * - Do not compute effective access in frontend code.
 * - These DTOs are configuration/read-model contracts only; runtime visibility remains backend-only.
 */

export type OperationalAccessActionKey =
  | 'tasks.view'
  | 'tasks.manage'
  | 'documents.review'
  | 'checklists.manage'
  | 'personal_cards.view';

export type OperationalAccessPrimaryWhereKey =
  | 'TENANT_WIDE'
  | 'ASSIGNED_AREAS'
  | 'RESPONSIBLE_FOR'
  | 'REVIEW_QUEUE';

export type OperationalAccessWhichRecordsKey =
  | 'all_tasks'
  | 'open_tasks'
  | 'documents_requiring_review'
  | 'active_checklists'
  | 'personal_cards_requiring_attention';

export type OperationalAccessActionCatalogItem = {
  key: OperationalAccessActionKey;
  label: string;
  description: string;
  category: string;
  allowedPrimaryWhere: OperationalAccessPrimaryWhereKey[];
  allowedWhichRecords: OperationalAccessWhichRecordsKey[];
};

export type OperationalAccessPrimaryWhereOption = {
  key: OperationalAccessPrimaryWhereKey;
  label: string;
  description: string;
};

export type OperationalAccessWhichRecordsOption = {
  key: OperationalAccessWhichRecordsKey;
  label: string;
  description: string;
  category: string;
};

export type OperationalAccessCatalogResponse = {
  catalog: {
    actions: OperationalAccessActionCatalogItem[];
    primaryWhere: OperationalAccessPrimaryWhereOption[];
    whichRecords: OperationalAccessWhichRecordsOption[];
    coverage: {
      assignedAreas: {
        available: false;
        reason: string;
      };
      responsibleFor: {
        available: true;
        targetType: 'tenant_membership';
        reason: string;
      };
    };
    deferred: string[];
  };
};

export type OperationalAccessGroupSummary = {
  id: string;
  name: string;
  description: string | null;
  level: 'AGENT';
  status: 'ACTIVE';
  memberCount: number;
  grantCount: number;
  responsibleForAssignmentCount: number;
};

export type OperationalAccessGroupsResponse = {
  groups: OperationalAccessGroupSummary[];
};

export type OperationalAccessGroupGrant = {
  id: string;
  actionKey: OperationalAccessActionKey;
  actionLabel: string;
  primaryWhere: OperationalAccessPrimaryWhereKey;
  primaryWhereLabel: string;
  whichRecordsKey: OperationalAccessWhichRecordsKey;
  whichRecordsLabel: string;
  createdAt: string;
  updatedAt: string;
};

export type OperationalAccessResponsibleForAssignment = {
  agentMembershipId: string;
  agentUserId: string;
  agentEmail: string;
  agentName: string | null;
  targetMembershipId: string;
  targetUserId: string;
  targetEmail: string;
  targetName: string | null;
  createdAt: string;
};

export type OperationalAccessGroupConfiguration = {
  group: OperationalAccessGroupSummary;
  grants: OperationalAccessGroupGrant[];
  responsibleFor: OperationalAccessResponsibleForAssignment[];
  safety: {
    runtimeVisibilityChanged: false;
    effectiveAccessResolverShipped: false;
    notes: string[];
  };
};

export type OperationalAccessGroupConfigurationResponse = {
  groupConfiguration: OperationalAccessGroupConfiguration;
};

export type OperationalAccessPerson = {
  membershipId: string;
  userId: string;
  email: string;
  name: string | null;
  role: 'ADMIN' | 'AGENT' | 'USER';
  status: 'ACTIVE';
  isAgent: boolean;
};

export type OperationalAccessPeopleResponse = {
  people: OperationalAccessPerson[];
};

export type SaveOperationalAccessGroupGrantsRequest = {
  grants: Array<{
    actionKey: OperationalAccessActionKey;
    primaryWhere: OperationalAccessPrimaryWhereKey;
    whichRecordsKey: OperationalAccessWhichRecordsKey;
  }>;
};

export type SaveOperationalAccessResponsibleForRequest = {
  assignments: Array<{
    agentMembershipId: string;
    targetMembershipId: string;
  }>;
};

export type OperationalAccessFoundationResponse = {
  catalog: OperationalAccessCatalogResponse['catalog'];
  groups: OperationalAccessGroupSummary[];
  people: OperationalAccessPerson[];
};
