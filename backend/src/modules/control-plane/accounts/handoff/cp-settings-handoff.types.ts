/**
 * backend/src/modules/control-plane/accounts/handoff/cp-settings-handoff.types.ts
 *
 * WHY:
 * - Defines the canonical internal producer contract for the future CP →
 *   Settings handoff.
 * - Gives the future Settings state engine one allowance-only snapshot shape to
 *   consume without re-reading CP authoring progress semantics.
 * - Keeps CP allowance truth, provisioning truth, and cascade-boundary truth
 *   explicit while the Settings engine is still absent from this repo.
 *
 * RULES:
 * - Internal integration contract only. No HTTP, Zod, or AppError here.
 * - Carry allowance truth and provisioning truth only — not CP Step 2 progress.
 * - Stay honest about the current repo state: producer-only, no live cascade.
 */

import type { PersonalFamilyKey, PersonalMinimumRequired } from '../cp-accounts.catalog';

export type CpSettingsHandoffCpStatus = 'Draft' | 'Active' | 'Disabled';

export type CpSettingsHandoffProvisioningState = 'NOT_PROVISIONED' | 'ACTIVE' | 'DISABLED';

export type CpSettingsHandoffMode = 'PRODUCER_ONLY';

export type CpSettingsHandoffEligibility =
  | 'READY_FOR_FUTURE_SETTINGS_CONSUMER'
  | 'BLOCKED_UNPUBLISHED_ACCOUNT';

export type CpSettingsHandoffConsumerState = {
  settingsEnginePresent: false;
  cascadeStatus: 'NOT_WIRED';
  blockingReasons: string[];
};

export type CpSettingsHandoffAccount = {
  accountId: string;
  accountKey: string;
  accountName: string;
  cpStatus: CpSettingsHandoffCpStatus;
  cpRevision: number;
};

export type CpSettingsHandoffProvisioning = {
  isProvisioned: boolean;
  tenantId: string | null;
  tenantKey: string | null;
  tenantName: string | null;
  tenantState: CpSettingsHandoffProvisioningState;
  publishedAt: Date | null;
};

export type CpSettingsAccessAllowance = {
  loginMethods: {
    password: boolean;
    google: boolean;
    microsoft: boolean;
  };
  mfaPolicy: {
    adminRequired: boolean;
    memberRequired: boolean;
  };
  signupPolicy: {
    publicSignup: boolean;
    adminInvitationsAllowed: boolean;
    allowedDomains: string[];
  };
};

export type CpSettingsAccountAllowance = {
  branding: {
    logo: boolean;
    menuColor: boolean;
    fontColor: boolean;
    welcomeMessage: boolean;
  };
  organizationStructure: {
    employers: boolean;
    locations: boolean;
  };
  companyCalendar: {
    allowed: boolean;
  };
};

export type CpSettingsModuleAllowance = {
  modules: {
    personal: boolean;
    documents: boolean;
    benefits: boolean;
    payments: boolean;
  };
};

export type CpSettingsPersonalFamilyAllowance = {
  familyKey: PersonalFamilyKey;
  isAllowed: boolean;
};

export type CpSettingsPersonalFieldAllowance = {
  familyKey: PersonalFamilyKey;
  fieldKey: string;
  isAllowed: boolean;
  defaultSelected: boolean;
  minimumRequired: PersonalMinimumRequired;
  isSystemManaged: boolean;
};

export type CpSettingsPersonalAllowance = {
  families: CpSettingsPersonalFamilyAllowance[];
  fields: CpSettingsPersonalFieldAllowance[];
};

export type CpSettingsIntegrationCapabilityAllowance = {
  capabilityKey: string;
  isAllowed: boolean;
};

export type CpSettingsIntegrationAllowance = {
  integrationKey: string;
  isAllowed: boolean;
  capabilities: CpSettingsIntegrationCapabilityAllowance[];
};

export type CpSettingsIntegrationAllowanceSnapshot = {
  integrations: CpSettingsIntegrationAllowance[];
};

export type CpSettingsAllowanceSnapshot = {
  access: CpSettingsAccessAllowance;
  account: CpSettingsAccountAllowance;
  modules: CpSettingsModuleAllowance;
  personal: CpSettingsPersonalAllowance;
  integrations: CpSettingsIntegrationAllowanceSnapshot;
};

export type CpSettingsHandoffSnapshot = {
  contractVersion: 1;
  producedAt: Date;
  mode: CpSettingsHandoffMode;
  eligibility: CpSettingsHandoffEligibility;
  consumer: CpSettingsHandoffConsumerState;
  account: CpSettingsHandoffAccount;
  provisioning: CpSettingsHandoffProvisioning;
  allowances: CpSettingsAllowanceSnapshot;
};
