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
    runtimeVisibilityChanged: boolean;
    effectiveAccessResolverShipped: boolean;
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

export type OperationalAccessSourcePath =
  | 'ADMIN_LEVEL'
  | 'USER_OWN_DATA'
  | 'AGENT_GROUP_TENANT_WIDE'
  | 'AGENT_GROUP_RESPONSIBLE_FOR'
  | 'OVERSIGHT_DIRECT'
  | 'OVERSIGHT_RESPONSIBLE_PEOPLE'
  | 'TEMPORARY_COVERAGE'
  | 'SPECIAL_ACCESS'
  | 'DENIED';

export type OperationalAccessFieldVisibility = {
  fieldKey: 'name' | 'email' | 'person.ssn' | 'person.date_of_birth';
  treatment: 'VISIBLE' | 'MASKED' | 'HIDDEN';
};

export type OperationalAccessDecision = {
  allowed: boolean;
  visible: boolean;
  editable: boolean;
  sourcePath: OperationalAccessSourcePath[];
  explanation: string[];
  fields: OperationalAccessFieldVisibility[];
};

export type PersonalCardFieldKey =
  | 'person.name'
  | 'person.work_email'
  | 'person.ssn'
  | 'person.date_of_birth';

export type PersonalCardField = {
  fieldKey: PersonalCardFieldKey;
  label: string;
  sensitivity: 'STANDARD' | 'SENSITIVE';
  treatment: 'VISIBLE' | 'MASKED' | 'HIDDEN';
  value: string | null;
};

export type PersonalCard = {
  membershipId: string;
  title: string | null;
  fields: PersonalCardField[];
  fieldVisibility: PersonalCardField[];
  sourcePath: OperationalAccessSourcePath[];
  explanation: string[];
};

export type PersonalCardsListResponse = {
  actionKey: 'personal_cards.view';
  module: 'personal_cards';
  whichRecordsApplied: 'personal_cards_requiring_attention';
  cards: PersonalCard[];
};

export type PersonalCardDetailResponse = {
  actionKey: 'personal_cards.view';
  module: 'personal_cards';
  whichRecordsApplied: 'personal_cards_requiring_attention';
  card: PersonalCard;
};

export type OperationalAccessOversight = {
  overseerMembershipId: string;
  targetMembershipId: string;
  includesResponsiblePeople: boolean;
  reason: string;
  reviewAt: string;
};

export type OperationalAccessTemporaryCoverage = {
  id: string;
  coveringMembershipId: string;
  coveredMembershipId: string;
  startsAt: string;
  expiresAt: string;
  reason: string;
  reviewAt: string | null;
};

export type OperationalAccessSpecialAccess = {
  id: string;
  membershipId: string;
  targetMembershipId: string;
  actionKey: OperationalAccessActionKey;
  reason: string;
  reviewAt: string;
  expiresAt: string;
};

export type OperationalAccessAdvancedCoverageResponse = {
  version: number;
  oversight: OperationalAccessOversight[];
  temporaryCoverage: OperationalAccessTemporaryCoverage[];
  specialAccess: OperationalAccessSpecialAccess[];
};

export type SaveOperationalAccessOversightRequest = {
  expectedVersion: number;
  replaceForMembershipIds?: string[];
  entries: Array<{
    overseerMembershipId: string;
    targetMembershipId: string;
    includesResponsiblePeople: boolean;
    reason: string;
    reviewAt: string;
  }>;
};

export type SaveOperationalAccessTemporaryCoverageRequest = {
  expectedVersion: number;
  replaceForMembershipIds?: string[];
  entries: Array<{
    coveringMembershipId: string;
    coveredMembershipId: string;
    startsAt: string;
    expiresAt: string;
    reason: string;
    reviewAt?: string | null;
  }>;
};

export type SaveOperationalAccessSpecialAccessRequest = {
  expectedVersion: number;
  replaceForMembershipIds?: string[];
  entries: Array<{
    membershipId: string;
    targetMembershipId: string;
    actionKey: OperationalAccessActionKey;
    reason: string;
    reviewAt: string;
    expiresAt: string;
  }>;
};
