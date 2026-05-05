/**
 * frontend/src/shared/settings/contracts.ts
 *
 * WHY:
 * - Central frontend contract layer for Settings-native read and write DTOs.
 * - Keeps `/admin`, `/admin/settings`, `/admin/settings/access`,
 *   `/admin/settings/account`, `/admin/settings/modules`,
 *   `/admin/settings/modules/personal`, and `/admin/settings/integrations`
 *   grounded in backend-owned shapes.
 * - Makes it explicit that Settings bootstrap truth now lives outside auth
 *   bootstrap even while auth still owns session and role routing.
 *
 * RULES:
 * - Mirror the current backend truth from:
 *   - backend/src/modules/settings/settings.types.ts
 *   - backend/docs/api/settings.md
 * - Do not invent frontend-only setup semantics here.
 * - Frontend may render these DTOs, but must never derive authoritative setup
 *   truth from local state.
 */

export type SettingsSetupStatus = 'NOT_STARTED' | 'IN_PROGRESS' | 'COMPLETE' | 'NEEDS_REVIEW';

export type SettingsSectionClassification =
  | 'REQUIRED_GATING'
  | 'LIVE_NON_GATING'
  | 'NAVIGATION_ONLY'
  | 'PLACEHOLDER_ONLY'
  | 'ABSENT';

export type SettingsOverviewCardKey =
  | 'access'
  | 'account'
  | 'modules'
  | 'integrations'
  | 'communications'
  | 'workspaceExperience';

export type SettingsAccountCardKey = 'branding' | 'orgStructure' | 'calendar';
export type SettingsModuleCardKey = 'personal' | 'documents' | 'benefits' | 'payments';

export type SettingsNextAction = {
  key: 'access' | 'modules';
  label: string;
  href: string;
};

export type SettingsBootstrapResponse = {
  overallStatus: SettingsSetupStatus;
  showSetupBanner: boolean;
  nextAction: SettingsNextAction | null;
};

export type SettingsOverviewCardResponse = {
  key: SettingsOverviewCardKey;
  title: string;
  description: string;
  href: string | null;
  classification: SettingsSectionClassification;
  status: SettingsSetupStatus | 'PLACEHOLDER';
  warnings: string[];
  isRequired: boolean;
  requiredReason: string | null;
};

export type SettingsOverviewResponse = {
  overallStatus: SettingsSetupStatus;
  nextAction: SettingsNextAction | null;
  cards: SettingsOverviewCardResponse[];
};

export type PlaceholderPageResponse = {
  key: 'communications' | 'workspaceExperience';
  title: string;
  status: 'PLACEHOLDER';
  treatment: 'PLACEHOLDER_ROUTE_ONLY';
  description: string;
  liveConfigurationAvailable: false;
  mutationEndpointsAvailable: false;
  notes: string[];
  backHref: string;
};

export type AccessSettingsRowStatus = 'READY' | 'WARNING' | 'BLOCKED';

export type AccessSettingsRowResponse = {
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

export type AccessSettingsGroupResponse = {
  key: 'loginMethods' | 'mfaPolicy' | 'signupPolicy';
  title: string;
  description: string;
  rows: AccessSettingsRowResponse[];
};

export type AccessSettingsResponse = {
  sectionKey: 'access';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  canAcknowledge: boolean;
  acknowledgeLabel: string;
  groups: AccessSettingsGroupResponse[];
  blockers: string[];
  warnings: string[];
  nextAction: SettingsNextAction | null;
};

export type AccountBrandingCardResponse = {
  key: 'branding';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  visibility: {
    logo: boolean;
    menuColor: boolean;
    fontColor: boolean;
    welcomeMessage: boolean;
  };
  values: {
    logoUrl: string | null;
    menuColor: string | null;
    fontColor: string | null;
    welcomeMessage: string | null;
  };
};

export type AccountOrgStructureCardResponse = {
  key: 'orgStructure';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  visibility: {
    employers: boolean;
    locations: boolean;
  };
  values: {
    employers: string[];
    locations: string[];
  };
};

export type AccountCalendarCardResponse = {
  key: 'calendar';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  visibility: {
    allowed: true;
  };
  values: {
    observedDates: string[];
  };
};

export type AccountSettingsCardResponse =
  | AccountBrandingCardResponse
  | AccountOrgStructureCardResponse
  | AccountCalendarCardResponse;

export type AccountSettingsResponse = {
  sectionKey: 'account';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  cards: AccountSettingsCardResponse[];
  warnings: string[];
  nextAction: SettingsNextAction | null;
};

export type ModulesHubModuleCardResponse = {
  key: SettingsModuleCardKey;
  title: string;
  description: string;
  classification: 'LIVE' | 'PLACEHOLDER';
  href: string | null;
  status: SettingsSetupStatus | 'PLACEHOLDER';
  warnings: string[];
  ctaLabel: string | null;
};

export type ModulesHubResponse = {
  title: string;
  description: string;
  cards: ModulesHubModuleCardResponse[];
  visibleModuleKeys: SettingsModuleCardKey[];
  nextAction: SettingsNextAction | null;
};

export type PersonalFamilyReviewDecision = 'IN_USE' | 'EXCLUDED';
export type PersonalFamilyReviewStatus = 'LOCKED_IN_USE' | 'REQUIRES_SAVE' | 'SAVED';
export type PersonalPanelStatus = 'NOT_STARTED' | 'IN_PROGRESS' | 'COMPLETE' | 'NEEDS_REVIEW';

export type PersonalFamilyReviewResponse = {
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

export type PersonalFieldConfigurationItemResponse = {
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

export type PersonalFieldConfigurationFamilyResponse = {
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
  fields: PersonalFieldConfigurationItemResponse[];
};

export type PersonalFieldConfigurationResponse = {
  key: 'fieldConfiguration';
  title: string;
  description: string;
  summary: string;
  status: PersonalPanelStatus;
  hiddenVsExcluded: {
    hidden: string;
    excluded: string;
  };
  families: PersonalFieldConfigurationFamilyResponse[];
};

export type PersonalSectionFieldResponse = {
  fieldKey: string;
  familyKey: string;
  label: string;
  order: number;
};

export type PersonalSectionResponse = {
  sectionId: string;
  name: string;
  order: number;
  fieldCount: number;
  fields: PersonalSectionFieldResponse[];
};

export type PersonalSectionBuilderResponse = {
  key: 'sectionBuilder';
  title: string;
  description: string;
  summary: string;
  status: PersonalPanelStatus;
  sections: PersonalSectionResponse[];
  emptySectionSaveBlocked: true;
  removeOnlyWhenEmpty: true;
};

export type PersonalProgressSummaryResponse = {
  reviewedFamiliesCount: number;
  totalAllowedFamilies: number;
  requiredFieldsReady: boolean;
  sectionAssignmentsReady: boolean;
  blockers: string[];
};

export type PersonalConflictGuidanceResponse = {
  summary: string;
  notes: string[];
};

export type PersonalSettingsResponse = {
  sectionKey: 'personal';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  warnings: string[];
  blockers: string[];
  nextAction: SettingsNextAction | null;
  progress: PersonalProgressSummaryResponse;
  familyReview: {
    key: 'familyReview';
    title: string;
    description: string;
    summary: string;
    status: PersonalPanelStatus;
    families: PersonalFamilyReviewResponse[];
  };
  fieldConfiguration: PersonalFieldConfigurationResponse;
  sectionBuilder: PersonalSectionBuilderResponse;
  conflictGuidance: PersonalConflictGuidanceResponse;
  saveActionLabel: 'Save Personal Configuration';
  stickySaveLabel: 'Save Personal Configuration';
};

export type IntegrationSsoProviderKey = 'google' | 'microsoft';
export type IntegrationDisplayStatus = 'HIDDEN' | 'READY' | 'NOT_IN_USE' | 'BLOCKED';
export type IntegrationReadinessStatus = 'READY' | 'SNAPSHOT_UNAVAILABLE' | 'STALE' | 'INVALID';

export type IntegrationSsoCardResponse = {
  integrationKey: 'integration.sso.google' | 'integration.sso.microsoft';
  providerKey: IntegrationSsoProviderKey;
  title: string;
  description: string;
  displayStatus: IntegrationDisplayStatus;
  statusLabel: string;
  visible: boolean;
  cpAllowed: boolean;
  loginMethodEnabled: boolean;
  tenantConfigurationAvailable: false;
  credentialEntryAvailable: false;
  connectionFlowAvailable: false;
  runtimeReadiness: {
    status: IntegrationReadinessStatus;
    checkedAt: string;
    detail: string | null;
  };
  warnings: string[];
  blockers: string[];
  resolutionHint: string | null;
  accessDependency: {
    loginMethodKey: 'auth.login.google' | 'auth.login.microsoft';
    enabled: boolean;
    description: string;
  };
};

export type DeferredIntegrationCardResponse = {
  integrationKey:
    | 'integration.adp'
    | 'integration.hint'
    | 'integration.istream'
    | 'integration.stripe';
  title: string;
  category: 'HRIS' | 'PAYMENTS';
  treatment: 'DEFERRED';
  description: string;
  reason: string;
  tenantConfigurationAvailable: false;
  credentialEntryAvailable: false;
  connectionFlowAvailable: false;
  syncEngineAvailable: false;
  mappingEditorAvailable: false;
  capabilities: Array<{
    capabilityKey: string;
    label: string;
    deferred: true;
  }>;
};

export type MarketplaceIntegrationResponse = {
  integrationKey: 'integration.marketplace';
  treatment: 'PLACEHOLDER_ONLY';
  visible: false;
  reason: string;
};

export type IntegrationsSettingsResponse = {
  sectionKey: 'integrations';
  title: string;
  description: string;
  status: SettingsSetupStatus;
  version: number;
  cpRevision: number;
  ssoIntegrations: IntegrationSsoCardResponse[];
  deferredIntegrations: DeferredIntegrationCardResponse[];
  marketplace: MarketplaceIntegrationResponse;
  warnings: string[];
  nextAction: SettingsNextAction | null;
};

export type SavePersonalSettingsRequest = {
  expectedVersion: number;
  expectedCpRevision: number;
  families: Array<{
    familyKey: string;
    reviewDecision: PersonalFamilyReviewDecision;
  }>;
  fields: Array<{
    fieldKey: string;
    included: boolean;
    required: boolean;
    masked: boolean;
  }>;
  sections: Array<{
    sectionId: string;
    name: string;
    order: number;
    fields: Array<{
      fieldKey: string;
      order: number;
    }>;
  }>;
};

export type SettingsMutationResultResponse = {
  section: {
    key: 'access' | 'account' | 'personal' | 'integrations';
    status: SettingsSetupStatus;
    version: number;
    cpRevision: number;
  };
  card?: {
    key: SettingsAccountCardKey;
    status: SettingsSetupStatus;
    version: number;
    cpRevision: number;
  };
  aggregate: {
    status: SettingsSetupStatus;
    version: number;
    cpRevision: number;
    nextAction: SettingsNextAction | null;
  };
  warnings: string[];
};
