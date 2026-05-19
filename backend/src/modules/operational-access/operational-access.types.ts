/**
 * backend/src/modules/operational-access/operational-access.types.ts
 *
 * WHY:
 * - Defines the Step 3 Operational Access configuration vocabulary.
 * - Keeps product-defined actions, Primary Where options, and Which Records
 *   choices centralized so tenants cannot invent arbitrary permission strings.
 *
 * RULES:
 * - Configuration only. No Effective Access Resolver lives here yet.
 * - No Oversight, Temporary Coverage, or Special Access types in this step.
 * - Frontend may render these DTOs but must not compute effective access.
 */

import type { PeopleTeamGroupStatus } from '../people-teams/people-teams.types';
import type { MembershipRole, MembershipStatus } from '../memberships/membership.types';

export const OPERATIONAL_ACCESS_ACTIONS = [
  {
    key: 'tasks.view',
    label: 'View tasks',
    description:
      'Can see task work lists that match this grant and future backend visibility checks.',
    category: 'Tasks',
    allowedPrimaryWhere: ['TENANT_WIDE', 'ASSIGNED_AREAS', 'RESPONSIBLE_FOR', 'REVIEW_QUEUE'],
    allowedWhichRecords: ['all_tasks', 'open_tasks'],
  },
  {
    key: 'tasks.manage',
    label: 'Manage tasks',
    description:
      'Can work on task records that match this grant and future backend visibility checks.',
    category: 'Tasks',
    allowedPrimaryWhere: ['TENANT_WIDE', 'ASSIGNED_AREAS', 'RESPONSIBLE_FOR', 'REVIEW_QUEUE'],
    allowedWhichRecords: ['open_tasks'],
  },
  {
    key: 'documents.review',
    label: 'Review documents',
    description: 'Can review documents that match this grant and future backend visibility checks.',
    category: 'Documents',
    allowedPrimaryWhere: ['ASSIGNED_AREAS', 'REVIEW_QUEUE'],
    allowedWhichRecords: ['documents_requiring_review'],
  },
  {
    key: 'checklists.manage',
    label: 'Manage checklists',
    description:
      'Can work on checklist instances that match this grant and future backend visibility checks.',
    category: 'Checklists',
    allowedPrimaryWhere: ['TENANT_WIDE', 'ASSIGNED_AREAS', 'RESPONSIBLE_FOR', 'REVIEW_QUEUE'],
    allowedWhichRecords: ['active_checklists'],
  },
  {
    key: 'personal_cards.view',
    label: 'View Personal Cards',
    description:
      'Can view masked Personal Card information that matches this grant and future backend visibility checks.',
    category: 'Personal',
    allowedPrimaryWhere: ['RESPONSIBLE_FOR', 'REVIEW_QUEUE'],
    allowedWhichRecords: ['personal_cards_requiring_attention'],
  },
] as const;

export type OperationalAccessActionKey = (typeof OPERATIONAL_ACCESS_ACTIONS)[number]['key'];

export const OPERATIONAL_ACCESS_ACTION_KEYS = OPERATIONAL_ACCESS_ACTIONS.map(
  (action) => action.key,
) as [OperationalAccessActionKey, ...OperationalAccessActionKey[]];

export const OPERATIONAL_ACCESS_PRIMARY_WHERE = [
  {
    key: 'TENANT_WIDE',
    label: 'Whole tenant',
    description: 'The group normally works across the whole tenant.',
  },
  {
    key: 'ASSIGNED_AREAS',
    label: 'Assigned Areas',
    description: 'The group normally works in explicit employer/location pairs.',
  },
  {
    key: 'RESPONSIBLE_FOR',
    label: 'Responsible For',
    description: 'The group normally works for exact people each Agent is responsible for.',
  },
  {
    key: 'REVIEW_QUEUE',
    label: 'Review Queue',
    description: 'The group normally works in a product-defined review or work queue.',
  },
] as const;

export type OperationalAccessPrimaryWhereKey =
  (typeof OPERATIONAL_ACCESS_PRIMARY_WHERE)[number]['key'];

export const OPERATIONAL_ACCESS_PRIMARY_WHERE_KEYS = OPERATIONAL_ACCESS_PRIMARY_WHERE.map(
  (option) => option.key,
) as [OperationalAccessPrimaryWhereKey, ...OperationalAccessPrimaryWhereKey[]];

export const OPERATIONAL_ACCESS_WHICH_RECORDS = [
  {
    key: 'all_tasks',
    label: 'All tasks in scope',
    description: 'Task records inside the selected Primary Where.',
    category: 'Tasks',
  },
  {
    key: 'open_tasks',
    label: 'Open tasks',
    description: 'Only open task records inside the selected Primary Where.',
    category: 'Tasks',
  },
  {
    key: 'documents_requiring_review',
    label: 'Documents requiring review',
    description: 'Documents that are in a review-needed queue.',
    category: 'Documents',
  },
  {
    key: 'active_checklists',
    label: 'Active checklist instances',
    description: 'Checklist instances currently active inside the selected Primary Where.',
    category: 'Checklists',
  },
  {
    key: 'personal_cards_requiring_attention',
    label: 'Personal Cards requiring attention',
    description: 'Personal Cards in a product-defined attention/review queue.',
    category: 'Personal',
  },
] as const;

export type OperationalAccessWhichRecordsKey =
  (typeof OPERATIONAL_ACCESS_WHICH_RECORDS)[number]['key'];

export const OPERATIONAL_ACCESS_WHICH_RECORDS_KEYS = OPERATIONAL_ACCESS_WHICH_RECORDS.map(
  (choice) => choice.key,
) as [OperationalAccessWhichRecordsKey, ...OperationalAccessWhichRecordsKey[]];

export type OperationalAccessAuditContext = {
  requestId: string | null;
  ip: string | null;
  userAgent: string | null;
  tenantId: string;
  userId: string;
  membershipId: string;
};

export type OperationalAccessActionCatalogItemDto = {
  key: OperationalAccessActionKey;
  label: string;
  description: string;
  category: string;
  allowedPrimaryWhere: OperationalAccessPrimaryWhereKey[];
  allowedWhichRecords: OperationalAccessWhichRecordsKey[];
};

export type OperationalAccessPrimaryWhereOptionDto = {
  key: OperationalAccessPrimaryWhereKey;
  label: string;
  description: string;
};

export type OperationalAccessWhichRecordsOptionDto = {
  key: OperationalAccessWhichRecordsKey;
  label: string;
  description: string;
  category: string;
};

export type OperationalAccessCatalogDto = {
  actions: OperationalAccessActionCatalogItemDto[];
  primaryWhere: OperationalAccessPrimaryWhereOptionDto[];
  whichRecords: OperationalAccessWhichRecordsOptionDto[];
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

export type OperationalAccessCatalogResponse = {
  catalog: OperationalAccessCatalogDto;
};

export type OperationalAccessGroupSummaryDto = {
  id: string;
  name: string;
  description: string | null;
  level: 'AGENT';
  status: Extract<PeopleTeamGroupStatus, 'ACTIVE'>;
  memberCount: number;
  grantCount: number;
  responsibleForAssignmentCount: number;
};

export type OperationalAccessGroupsResponse = {
  groups: OperationalAccessGroupSummaryDto[];
};

export type OperationalAccessGroupGrantDto = {
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

export type OperationalAccessResponsibleForAssignmentDto = {
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

export type OperationalAccessGroupConfigurationDto = {
  group: OperationalAccessGroupSummaryDto;
  grants: OperationalAccessGroupGrantDto[];
  responsibleFor: OperationalAccessResponsibleForAssignmentDto[];
  safety: {
    runtimeVisibilityChanged: false;
    effectiveAccessResolverShipped: false;
    notes: string[];
  };
};

export type OperationalAccessGroupConfigurationResponse = {
  groupConfiguration: OperationalAccessGroupConfigurationDto;
};

export type OperationalAccessPersonDto = {
  membershipId: string;
  userId: string;
  email: string;
  name: string | null;
  role: MembershipRole;
  status: Extract<MembershipStatus, 'ACTIVE'>;
  isAgent: boolean;
};

export type OperationalAccessPeopleResponse = {
  people: OperationalAccessPersonDto[];
};
