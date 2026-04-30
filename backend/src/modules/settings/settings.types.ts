/**
 * backend/src/modules/settings/settings.types.ts
 *
 * WHY:
 * - Centralises the Settings persistence vocabulary, read DTO contracts, and
 *   stable section/classification constants used by the Settings state engine,
 *   read surfaces, and the shipped write surfaces.
 * - Gives migrations, repos, services, and frontend contracts one shared
 *   source for statuses, section keys, route ownership, and DTO shapes.
 *
 * RULES:
 * - Pure types/constants only.
 * - No DB access, no HTTP framework types, no UI implementation details.
 * - DTOs here are backend-owned contracts; frontend may render them but must
 *   never derive authoritative completion truth from local state.
 */

export const SETTINGS_SETUP_STATUSES = [
  'NOT_STARTED',
  'IN_PROGRESS',
  'COMPLETE',
  'NEEDS_REVIEW',
] as const;

export type SettingsSetupStatus = (typeof SETTINGS_SETUP_STATUSES)[number];

export const LIVE_SETTINGS_SECTION_KEYS = [
  'access',
  'account',
  'personal',
  'integrations',
] as const;

export type SettingsSectionKey = (typeof LIVE_SETTINGS_SECTION_KEYS)[number];

export const SETTINGS_REQUIRED_GATING_SECTION_KEYS = ['access', 'personal'] as const;

export type SettingsRequiredGatingSectionKey =
  (typeof SETTINGS_REQUIRED_GATING_SECTION_KEYS)[number];

export const SETTINGS_LIVE_NON_GATING_SECTION_KEYS = ['account', 'integrations'] as const;

export type SettingsLiveNonGatingSectionKey =
  (typeof SETTINGS_LIVE_NON_GATING_SECTION_KEYS)[number];

export const SETTINGS_OVERVIEW_CARD_KEYS = [
  'access',
  'account',
  'modules',
  'integrations',
  'communications',
  'workspaceExperience',
] as const;

export type SettingsOverviewCardKey = (typeof SETTINGS_OVERVIEW_CARD_KEYS)[number];

export const SETTINGS_PLACEHOLDER_CARD_KEYS = ['communications', 'workspaceExperience'] as const;

export type SettingsPlaceholderCardKey = (typeof SETTINGS_PLACEHOLDER_CARD_KEYS)[number];

export const SETTINGS_ACCOUNT_CARD_KEYS = ['branding', 'orgStructure', 'calendar'] as const;

export type SettingsAccountCardKey = (typeof SETTINGS_ACCOUNT_CARD_KEYS)[number];

export const SETTINGS_MODULE_CARD_KEYS = ['personal', 'documents', 'benefits', 'payments'] as const;

export type SettingsModuleCardKey = (typeof SETTINGS_MODULE_CARD_KEYS)[number];

export const PERSONAL_FAMILY_REVIEW_DECISIONS = ['IN_USE', 'EXCLUDED'] as const;
export type PersonalFamilyReviewDecision = (typeof PERSONAL_FAMILY_REVIEW_DECISIONS)[number];

export const PERSONAL_FAMILY_REVIEW_STATUSES = ['LOCKED_IN_USE', 'REQUIRES_SAVE', 'SAVED'] as const;
export type PersonalFamilyReviewStatus = (typeof PERSONAL_FAMILY_REVIEW_STATUSES)[number];

export const PERSONAL_PANEL_STATUSES = [
  'NOT_STARTED',
  'IN_PROGRESS',
  'COMPLETE',
  'NEEDS_REVIEW',
] as const;
export type PersonalPanelStatus = (typeof PERSONAL_PANEL_STATUSES)[number];

export const SETTINGS_REASON_CODES = {
  FOUNDATION_INITIALIZED: 'FOUNDATION_INITIALIZED',
  TENANT_BOOTSTRAP_FOUNDATION: 'TENANT_BOOTSTRAP_FOUNDATION',
  CP_PROVISIONING_FOUNDATION: 'CP_PROVISIONING_FOUNDATION',
  LEGACY_AUTH_ACK_BRIDGE: 'LEGACY_AUTH_ACK_BRIDGE',
  ACCESS_ACKNOWLEDGED: 'ACCESS_ACKNOWLEDGED',
  ACCOUNT_BRANDING_SAVED: 'ACCOUNT_BRANDING_SAVED',
  ACCOUNT_ORG_STRUCTURE_SAVED: 'ACCOUNT_ORG_STRUCTURE_SAVED',
  ACCOUNT_CALENDAR_SAVED: 'ACCOUNT_CALENDAR_SAVED',
  PERSONAL_CONFIGURATION_SAVED: 'PERSONAL_CONFIGURATION_SAVED',
  CP_REQUIRED_TARGET_REMOVED: 'CP_REQUIRED_TARGET_REMOVED',
  CP_OPTIONAL_TARGET_REMOVED: 'CP_OPTIONAL_TARGET_REMOVED',
  CP_REQUIRED_TARGET_ADDED: 'CP_REQUIRED_TARGET_ADDED',
  CP_REQUIRED_TARGET_CHANGED: 'CP_REQUIRED_TARGET_CHANGED',
  CP_INTEGRATION_DEPENDENCY_CHANGED: 'CP_INTEGRATION_DEPENDENCY_CHANGED',
  CP_REVISION_SYNC: 'CP_REVISION_SYNC',
} as const;

export type SettingsReasonCode = (typeof SETTINGS_REASON_CODES)[keyof typeof SETTINGS_REASON_CODES];

export type TenantSetupStateRecord = {
  tenantId: string;
  overallStatus: SettingsSetupStatus;
  version: number;
  appliedCpRevision: number;
  lastTransitionReasonCode: string | null;
  lastTransitionAt: Date;
  lastSavedAt: Date | null;
  lastSavedByUserId: string | null;
  lastReviewedAt: Date | null;
  lastReviewedByUserId: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type TenantSetupSectionStateRecord = {
  tenantId: string;
  sectionKey: SettingsSectionKey;
  status: SettingsSetupStatus;
  version: number;
  appliedCpRevision: number;
  lastTransitionReasonCode: string | null;
  lastTransitionAt: Date;
  lastSavedAt: Date | null;
  lastSavedByUserId: string | null;
  lastReviewedAt: Date | null;
  lastReviewedByUserId: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type SettingsSectionClassification =
  | 'REQUIRED_GATING'
  | 'LIVE_NON_GATING'
  | 'NAVIGATION_ONLY'
  | 'PLACEHOLDER_ONLY'
  | 'ABSENT';

export type SettingsSectionRouteMeta = {
  key: SettingsOverviewCardKey;
  title: string;
  description: string;
  href: string | null;
  classification: SettingsSectionClassification;
  sectionKey: SettingsSectionKey | null;
};

export const SETTINGS_SECTION_ROUTES: Record<SettingsOverviewCardKey, SettingsSectionRouteMeta> = {
  access: {
    key: 'access',
    title: 'Access & Security',
    description: 'Review the platform-managed access envelope for this workspace.',
    href: '/admin/settings/access',
    classification: 'REQUIRED_GATING',
    sectionKey: 'access',
  },
  account: {
    key: 'account',
    title: 'Account Settings',
    description: 'Configure branding, organization structure, and company calendar values.',
    href: '/admin/settings/account',
    classification: 'LIVE_NON_GATING',
    sectionKey: 'account',
  },
  modules: {
    key: 'modules',
    title: 'Modules',
    description: 'Open the modules hub. Personal is the only live configurable child in v1.',
    href: '/admin/settings/modules',
    classification: 'NAVIGATION_ONLY',
    sectionKey: null,
  },
  integrations: {
    key: 'integrations',
    title: 'Integrations',
    description: 'View informational SSO integration readiness and deferred integration cards.',
    href: '/admin/settings/integrations',
    classification: 'LIVE_NON_GATING',
    sectionKey: 'integrations',
  },
  communications: {
    key: 'communications',
    title: 'Communications',
    description: 'Placeholder only in v1. Email templates and notification rules are not live yet.',
    href: '/admin/settings/communications',
    classification: 'PLACEHOLDER_ONLY',
    sectionKey: null,
  },
  workspaceExperience: {
    key: 'workspaceExperience',
    title: 'Workspace Experience',
    description: 'Placeholder only in v1. Workspace Experience configuration remains deferred.',
    href: null,
    classification: 'PLACEHOLDER_ONLY',
    sectionKey: null,
  },
};

export type SettingsNextAction = {
  key: Extract<SettingsOverviewCardKey, 'access' | 'modules'>;
  label: string;
  href: string;
};

export type SettingsBootstrapDto = {
  overallStatus: SettingsSetupStatus;
  showSetupBanner: boolean;
  nextAction: SettingsNextAction | null;
};

export type SettingsOverviewCardDto = {
  key: SettingsOverviewCardKey;
  title: string;
  description: string;
  href: string | null;
  classification: SettingsSectionClassification;
  status: SettingsSetupStatus | 'PLACEHOLDER';
  warnings: string[];
  isRequired: boolean;
};

export type SettingsOverviewDto = {
  overallStatus: SettingsSetupStatus;
  nextAction: SettingsNextAction | null;
  cards: SettingsOverviewCardDto[];
};

export type AccessSettingsRowStatus = 'READY' | 'WARNING' | 'BLOCKED';

export type AccessSettingsRowDto = {
  key: string;
  label: string;
  value: string;
  readOnly: true;
  managedBy: 'CONTROL_PLANE' | 'PLATFORM';
  status: AccessSettingsRowStatus;
  warning: string | null;
  blocker: string | null;
  resolutionHref: string | null;
};

export type AccessSettingsGroupDto = {
  key: 'loginMethods' | 'mfaPolicy' | 'signupPolicy';
  title: string;
  description: string;
  rows: AccessSettingsRowDto[];
};

export type AccessSettingsDto = {
  sectionKey: 'access';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  canAcknowledge: boolean;
  acknowledgeLabel: string;
  groups: AccessSettingsGroupDto[];
  blockers: string[];
  warnings: string[];
  nextAction: SettingsNextAction | null;
};

export type AccountBrandingValuesDto = {
  logoUrl: string | null;
  menuColor: string | null;
  fontColor: string | null;
  welcomeMessage: string | null;
};

export type AccountBrandingVisibilityDto = {
  logo: boolean;
  menuColor: boolean;
  fontColor: boolean;
  welcomeMessage: boolean;
};

export type AccountBrandingCardDto = {
  key: 'branding';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  visibility: AccountBrandingVisibilityDto;
  values: AccountBrandingValuesDto;
};

export type AccountOrgStructureValuesDto = {
  employers: string[];
  locations: string[];
};

export type AccountOrgStructureVisibilityDto = {
  employers: boolean;
  locations: boolean;
};

export type AccountOrgStructureCardDto = {
  key: 'orgStructure';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  visibility: AccountOrgStructureVisibilityDto;
  values: AccountOrgStructureValuesDto;
};

export type AccountCalendarValuesDto = {
  observedDates: string[];
};

export type AccountCalendarCardDto = {
  key: 'calendar';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  visibility: {
    allowed: true;
  };
  values: AccountCalendarValuesDto;
};

export type AccountSettingsCardDto =
  | AccountBrandingCardDto
  | AccountOrgStructureCardDto
  | AccountCalendarCardDto;

export type AccountSettingsDto = {
  sectionKey: 'account';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  cards: AccountSettingsCardDto[];
  warnings: string[];
  nextAction: SettingsNextAction | null;
};

export type ModulesHubModuleCardDto = {
  key: SettingsModuleCardKey;
  title: string;
  description: string;
  classification: 'LIVE' | 'PLACEHOLDER';
  href: string | null;
  status: SettingsSetupStatus | 'PLACEHOLDER';
  warnings: string[];
  ctaLabel: string | null;
};

export type ModulesHubDto = {
  title: string;
  description: string;
  cards: ModulesHubModuleCardDto[];
  visibleModuleKeys: SettingsModuleCardKey[];
  nextAction: SettingsNextAction | null;
};

export type PersonalFamilyReviewItemDto = {
  familyKey: string;
  label: string;
  reviewDecision: PersonalFamilyReviewDecision;
  reviewStatus: PersonalFamilyReviewStatus;
  isAllowed: true;
  canExclude: boolean;
  lockedReason: string | null;
  allowedFieldCount: number;
  includedFieldCount: number;
  requiredFieldKeys: string[];
  notes: string[];
  warnings: string[];
  blockers: string[];
};

export type PersonalFieldIncludeRule = 'LOCKED_INCLUDED' | 'TENANT_CHOICE';
export type PersonalFieldRequiredRule = 'LOCKED_REQUIRED' | 'TENANT_CHOICE' | 'SYSTEM_MANAGED';
export type PersonalFieldMaskingRule = 'TENANT_CHOICE' | 'SYSTEM_MANAGED';

export type PersonalFieldConfigurationItemDto = {
  familyKey: string;
  fieldKey: string;
  label: string;
  notes: string;
  minimumRequired: 'none' | 'required' | 'auto';
  isSystemManaged: boolean;
  included: boolean;
  required: boolean;
  masked: boolean;
  includeRule: PersonalFieldIncludeRule;
  requiredRule: PersonalFieldRequiredRule;
  maskingRule: PersonalFieldMaskingRule;
  canToggleInclude: boolean;
  canToggleRequired: boolean;
  canToggleMasking: boolean;
  warnings: string[];
  blockers: string[];
};

export type PersonalFieldConfigurationFamilyDto = {
  familyKey: string;
  label: string;
  reviewDecision: PersonalFamilyReviewDecision;
  canExclude: boolean;
  exclusionLockedReason: string | null;
  visibleFieldCount: number;
  includedFieldCount: number;
  minimumRequiredFieldCount: number;
  systemManagedFieldCount: number;
  notes: string[];
  fields: PersonalFieldConfigurationItemDto[];
};

export type PersonalFieldConfigurationDto = {
  key: 'fieldConfiguration';
  title: string;
  description: string;
  summary: string;
  status: PersonalPanelStatus;
  hiddenVsExcluded: {
    hidden: string;
    excluded: string;
  };
  families: PersonalFieldConfigurationFamilyDto[];
};

export type PersonalSectionFieldDto = {
  fieldKey: string;
  familyKey: string;
  label: string;
  order: number;
};

export type PersonalSectionDto = {
  sectionId: string;
  name: string;
  order: number;
  fieldCount: number;
  fields: PersonalSectionFieldDto[];
};

export type PersonalSectionBuilderDto = {
  key: 'sectionBuilder';
  title: string;
  description: string;
  summary: string;
  status: PersonalPanelStatus;
  sections: PersonalSectionDto[];
  emptySectionSaveBlocked: true;
  removeOnlyWhenEmpty: true;
};

export type PersonalProgressSummaryDto = {
  reviewedFamiliesCount: number;
  totalAllowedFamilies: number;
  requiredFieldsReady: boolean;
  sectionAssignmentsReady: boolean;
  blockers: string[];
};

export type PersonalConflictGuidanceDto = {
  summary: string;
  notes: string[];
};

export type PersonalSettingsDto = {
  sectionKey: 'personal';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  warnings: string[];
  blockers: string[];
  nextAction: SettingsNextAction | null;
  progress: PersonalProgressSummaryDto;
  familyReview: {
    key: 'familyReview';
    title: string;
    description: string;
    summary: string;
    status: PersonalPanelStatus;
    families: PersonalFamilyReviewItemDto[];
  };
  fieldConfiguration: PersonalFieldConfigurationDto;
  sectionBuilder: PersonalSectionBuilderDto;
  conflictGuidance: PersonalConflictGuidanceDto;
  saveActionLabel: 'Save Personal Configuration';
  stickySaveLabel: 'Save Personal Configuration';
};

export type SettingsMutationSectionSummaryDto = {
  key: SettingsSectionKey;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
};

export type SettingsMutationCardSummaryDto = {
  key: SettingsAccountCardKey;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
};

export type SettingsMutationAggregateSummaryDto = {
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  nextAction: SettingsNextAction | null;
};

export type SettingsMutationResultDto = {
  section: SettingsMutationSectionSummaryDto;
  card?: SettingsMutationCardSummaryDto;
  aggregate: SettingsMutationAggregateSummaryDto;
  warnings: string[];
};

export type SettingsBootstrapResponse = SettingsBootstrapDto;
export type SettingsOverviewResponse = SettingsOverviewDto;
export type AccessSettingsResponse = AccessSettingsDto;
export type AccountSettingsResponse = AccountSettingsDto;
export type ModulesHubResponse = ModulesHubDto;
export type PersonalSettingsResponse = PersonalSettingsDto;
export type SettingsMutationResponse = SettingsMutationResultDto;

export type SettingsStateBundle = {
  aggregate: TenantSetupStateRecord;
  sections: Record<SettingsSectionKey, TenantSetupSectionStateRecord>;
};

export type SettingsSectionTransitionInput = {
  tenantId: string;
  sectionKey: SettingsSectionKey;
  nextStatus: SettingsSetupStatus;
  appliedCpRevision: number;
  reasonCode: SettingsReasonCode;
  transitionAt: Date;
  actorUserId?: string | null;
  markReviewed?: boolean;
  markSaved?: boolean;
};

export type SettingsAggregateTransitionInput = {
  tenantId: string;
  nextStatus: SettingsSetupStatus;
  appliedCpRevision: number;
  reasonCode: SettingsReasonCode;
  transitionAt: Date;
  actorUserId?: string | null;
  markReviewed?: boolean;
  markSaved?: boolean;
};

export type SettingsSectionRevisionSyncInput = {
  tenantId: string;
  sectionKey: SettingsSectionKey;
  appliedCpRevision: number;
  syncedAt: Date;
};

export type SettingsAggregateRevisionSyncInput = {
  tenantId: string;
  appliedCpRevision: number;
  syncedAt: Date;
};
