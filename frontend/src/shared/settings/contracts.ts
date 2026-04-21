/**
 * frontend/src/shared/settings/contracts.ts
 *
 * WHY:
 * - Central frontend contract layer for Settings-native read DTOs.
 * - Keeps `/admin` and `/admin/settings` grounded in the backend-owned
 *   bootstrap/overview shapes instead of ad-hoc inline types.
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
