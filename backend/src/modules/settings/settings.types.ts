/**
 * backend/src/modules/settings/settings.types.ts
 *
 * WHY:
 * - Centralises the foundational Settings persistence vocabulary introduced by
 *   Step 10 Phase 1.
 * - Gives migrations, low-level repos, and later state-engine work one shared
 *   source for setup statuses, live section keys, and bridge reason codes.
 *
 * RULES:
 * - Pure types/constants only.
 * - No DB access, no HTTP contracts, no UI labels.
 * - This file defines only the Phase 1 persistence vocabulary, not the full
 *   future Settings DTO surface.
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

export const SETTINGS_REASON_CODES = {
  FOUNDATION_INITIALIZED: 'FOUNDATION_INITIALIZED',
  TENANT_BOOTSTRAP_FOUNDATION: 'TENANT_BOOTSTRAP_FOUNDATION',
  CP_PROVISIONING_FOUNDATION: 'CP_PROVISIONING_FOUNDATION',
  LEGACY_AUTH_ACK_BRIDGE: 'LEGACY_AUTH_ACK_BRIDGE',
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
