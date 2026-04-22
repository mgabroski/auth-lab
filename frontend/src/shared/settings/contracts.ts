/**
 * frontend/src/shared/settings/contracts.ts
 *
 * WHY:
 * - Central frontend contract layer for Settings-native read and write DTOs.
 * - Keeps `/admin`, `/admin/settings`, `/admin/settings/access`,
 *   `/admin/settings/account`, `/admin/settings/modules`, and
 *   `/admin/settings/modules/personal` grounded in backend-owned shapes.
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
};

export type SettingsOverviewResponse = {
  overallStatus: SettingsSetupStatus;
  nextAction: SettingsNextAction | null;
  cards: SettingsOverviewCardResponse[];
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

export type PersonalFamilyReviewResponse = {
  familyKey: string;
  label: string;
  reviewDecision: 'UNREVIEWED';
  reviewStatus: 'NOT_STARTED';
  allowedFieldCount: number;
  defaultSelectedFieldCount: number;
  containsLockedRequiredFields: boolean;
  canExclude: boolean;
  requiredFieldKeys: string[];
  systemManagedFieldKeys: string[];
  notes: string[];
};

export type PersonalStepPanelResponse = {
  key: 'familyReview' | 'fieldConfiguration' | 'sectionBuilder';
  title: string;
  description: string;
  status: 'NOT_STARTED' | 'CURRENT_FOUNDATION' | 'FUTURE_PHASE';
  isLiveInCurrentRepo: boolean;
  summary: string;
};

export type PersonalFieldConfigurationReadiness =
  | 'CP_DEFAULT_SELECTED'
  | 'AVAILABLE_TO_INCLUDE'
  | 'SYSTEM_MANAGED';

export type PersonalFieldRequiredRule = 'LOCKED_REQUIRED' | 'TENANT_CHOICE' | 'SYSTEM_MANAGED';

export type PersonalFieldMaskingRule = 'TENANT_CHOICE_WHEN_INCLUDED' | 'LOCKED_SYSTEM_MANAGED';

export type PersonalFieldPresentationState = 'CONFIGURABLE' | 'READ_ONLY_SYSTEM_MANAGED';

export type PersonalFieldConfigurationItemResponse = {
  familyKey: string;
  fieldKey: string;
  label: string;
  notes: string;
  minimumRequired: 'none' | 'required' | 'auto';
  isSystemManaged: boolean;
  presentationState: PersonalFieldPresentationState;
  readiness: PersonalFieldConfigurationReadiness;
  requiredRule: PersonalFieldRequiredRule;
  maskingRule: PersonalFieldMaskingRule;
  canBeExcludedLater: boolean;
  canToggleRequiredLater: boolean;
  canToggleMaskingLater: boolean;
  warnings: string[];
  blockers: string[];
};

export type PersonalFieldConfigurationFamilyResponse = {
  familyKey: string;
  label: string;
  canExclude: boolean;
  exclusionLockedReason: string | null;
  visibleFieldCount: number;
  defaultSelectedFieldCount: number;
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
  status: 'CURRENT_FOUNDATION';
  isLiveInCurrentRepo: true;
  hiddenVsExcluded: {
    hidden: string;
    excluded: string;
  };
  conflictGuidance: {
    version: number;
    cpRevision: number;
    summary: string;
    notes: string[];
  };
  families: PersonalFieldConfigurationFamilyResponse[];
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
  moduleEnabled: boolean;
  familyReview: {
    title: string;
    description: string;
    summary: string;
    families: PersonalFamilyReviewResponse[];
  };
  fieldConfiguration: PersonalFieldConfigurationResponse;
  sectionBuilder: PersonalStepPanelResponse;
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
