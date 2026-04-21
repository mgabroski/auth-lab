/**
 * frontend/src/shared/settings/contracts.ts
 *
 * WHY:
 * - Central frontend contract layer for Settings-native read and write DTOs.
 * - Keeps `/admin`, `/admin/settings`, and `/admin/settings/access` grounded in
 *   backend-owned shapes instead of ad-hoc inline types.
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

export type SettingsMutationResultResponse = {
  section: {
    key: 'access' | 'account' | 'personal' | 'integrations';
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
