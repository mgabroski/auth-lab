/**
 * backend/src/modules/control-plane/accounts/cp-accounts.types.ts
 *
 * WHY:
 * - Domain and response types for the Control Plane accounts subdomain.
 * - Backend controllers and services use these types to keep CP DTOs explicit.
 * - Carries backend-owned review composition, activation-readiness truth, and
 *   provisioning-result truth without leaking persistence rows.
 *
 * RULES:
 * - No Kysely imports here.
 * - No Zod imports here.
 * - No AppError here.
 */

import type {
  CpSetupGroupSlug,
  PersonalFamilyKey,
  PersonalMinimumRequired,
} from './cp-accounts.catalog';
import type { CpSettingsHandoffSnapshot } from './handoff/cp-settings-handoff.types';

export type CpStatus = 'Draft' | 'Active' | 'Disabled';

export type CpSetupGroupSummary = {
  slug: CpSetupGroupSlug;
  title: string;
  isRequired: boolean;
  configured: boolean;
};

export type CpStep2Progress = {
  configuredCount: number;
  totalCount: number;
  requiredConfiguredCount: number;
  requiredTotalCount: number;
  canContinueToReview: boolean;
  groups: CpSetupGroupSummary[];
};

export type CpAccountListRow = {
  id: string;
  accountName: string;
  accountKey: string;
  cpStatus: CpStatus;
  cpRevision: number;
  step2Progress: CpStep2Progress;
};

export type CpAccessConfig = {
  configured: boolean;
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

export type CpAccountSettingsConfig = {
  configured: boolean;
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

export type CpModuleSettingsConfig = {
  configured: boolean;
  moduleDecisionsSaved: boolean;
  personalSubpageSaved: boolean;
  modules: {
    personal: boolean;
    documents: boolean;
    benefits: boolean;
    payments: boolean;
  };
};

export type CpPersonalField = {
  familyKey: PersonalFamilyKey;
  fieldKey: string;
  label: string;
  notes: string;
  isAllowed: boolean;
  defaultSelected: boolean;
  minimumRequired: PersonalMinimumRequired;
  isSystemManaged: boolean;
  allowedLocked: boolean;
};

export type CpPersonalFamily = {
  familyKey: PersonalFamilyKey;
  label: string;
  isAllowed: boolean;
  allowedLocked: boolean;
  fields: CpPersonalField[];
};

export type CpPersonalConfig = {
  saved: boolean;
  families: CpPersonalFamily[];
};

export type CpIntegrationCapability = {
  capabilityKey: string;
  label: string;
  isAllowed: boolean;
};

export type CpIntegrationConfigItem = {
  integrationKey: string;
  label: string;
  isAllowed: boolean;
  capabilities: CpIntegrationCapability[];
};

export type CpIntegrationsConfig = {
  configured: boolean;
  integrations: CpIntegrationConfigItem[];
};

export type CpAccountDetail = {
  id: string;
  accountName: string;
  accountKey: string;
  cpStatus: CpStatus;
  cpRevision: number;
  createdAt: Date;
  updatedAt: Date;
  step2Progress: CpStep2Progress;
  access: CpAccessConfig;
  accountSettings: CpAccountSettingsConfig;
  moduleSettings: CpModuleSettingsConfig;
  personal: CpPersonalConfig;
  integrations: CpIntegrationsConfig;
  settingsHandoff: CpSettingsHandoffSnapshot;
};

export type CpReviewLine = {
  label: string;
  value: string;
};

export type CpReviewSectionKey =
  | 'identity'
  | 'access'
  | 'accountSettings'
  | 'moduleSettings'
  | 'personalAllowances'
  | 'integrations';

export type CpReviewSection = {
  key: CpReviewSectionKey;
  title: string;
  lines: CpReviewLine[];
};

export type CpActivationReadinessCheckCode =
  | 'ACCOUNT_IDENTITY_PRESENT'
  | 'ACCESS_DECISIONS_MADE'
  | 'LOGIN_METHOD_SELECTED'
  | 'ACCOUNT_SETTINGS_DECISIONS_MADE'
  | 'MODULE_DECISIONS_MADE'
  | 'PERSONAL_CATALOG_DEFINED'
  | 'INTEGRATION_DECISIONS_RELEVANT';

export type CpActivationReadinessCheck = {
  code: CpActivationReadinessCheckCode;
  label: string;
  passed: boolean;
  detail: string;
};

export type CpActivationReadiness = {
  isReady: boolean;
  checks: CpActivationReadinessCheck[];
  blockingReasons: string[];
};

export type CpProvisioningState = 'NOT_PROVISIONED' | 'ACTIVE' | 'DISABLED';

export type CpProvisioningResult = {
  isProvisioned: boolean;
  tenantId: string | null;
  tenantKey: string | null;
  tenantName: string | null;
  tenantState: CpProvisioningState;
  publishedAt: Date | null;
};

export type CpAccountReview = {
  account: CpAccountDetail;
  sections: CpReviewSection[];
  activationReadiness: CpActivationReadiness;
  provisioning: CpProvisioningResult;
};
