/**
 * cp/src/features/accounts/contracts.ts
 *
 * WHY:
 * - Shared CP frontend type contracts for accounts, Step 2 group DTOs, review
 *   flows, and same-origin mutation payloads.
 */

export type AccountFlowMode = 'create' | 'edit';

export type SetupGroupSlug =
  | 'access-identity-security'
  | 'account-settings'
  | 'module-settings'
  | 'integrations-marketplace';

export type PersonalFamilyKey =
  | 'identity'
  | 'contact'
  | 'address'
  | 'dependents'
  | 'emergency'
  | 'identifiers'
  | 'signature';

export type CpStatus = 'Draft' | 'Active' | 'Disabled';

export type SetupGroupDefinition = {
  slug: SetupGroupSlug;
  title: string;
  shortLabel: string;
  description: string;
  isRequired: boolean;
};

export type StepDefinition = {
  stepNumber: 1 | 2 | 3;
  name: string;
};

export type FooterAction = {
  label: string;
  ariaLabel?: string;
  href?: string;
  variant?: 'ghost' | 'secondary' | 'primary';
  disabled?: boolean;
  onClick?: () => void;
};

export type CpStep2Progress = {
  configuredCount: number;
  totalCount: number;
  requiredConfiguredCount: number;
  requiredTotalCount: number;
  canContinueToReview: boolean;
  groups: Array<{
    slug: SetupGroupSlug;
    title: string;
    isRequired: boolean;
    configured: boolean;
  }>;
};

export type ControlPlaneAccountListItem = {
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
  minimumRequired: 'none' | 'required' | 'auto';
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

export type CpIntegrationConfigItem = {
  integrationKey: string;
  label: string;
  isAllowed: boolean;
  capabilities: Array<{
    capabilityKey: string;
    label: string;
    isAllowed: boolean;
  }>;
};

export type CpIntegrationsConfig = {
  configured: boolean;
  integrations: CpIntegrationConfigItem[];
};

export type CpSettingsHandoffSnapshot = {
  contractVersion: 1;
  producedAt: string;
  mode: 'PRODUCER_ONLY';
  eligibility: 'READY_FOR_FUTURE_SETTINGS_CONSUMER' | 'BLOCKED_UNPUBLISHED_ACCOUNT';
  consumer: {
    settingsEnginePresent: false;
    cascadeStatus: 'NOT_WIRED';
    blockingReasons: string[];
  };
  account: {
    accountId: string;
    accountKey: string;
    accountName: string;
    cpStatus: CpStatus;
    cpRevision: number;
  };
  provisioning: {
    isProvisioned: boolean;
    tenantId: string | null;
    tenantKey: string | null;
    tenantName: string | null;
    tenantState: CpProvisioningState;
    publishedAt: string | null;
  };
  allowances: {
    access: Omit<CpAccessConfig, 'configured'>;
    account: Omit<CpAccountSettingsConfig, 'configured'>;
    modules: {
      modules: CpModuleSettingsConfig['modules'];
    };
    personal: {
      families: Array<{
        familyKey: PersonalFamilyKey;
        isAllowed: boolean;
      }>;
      fields: Array<{
        familyKey: PersonalFamilyKey;
        fieldKey: string;
        isAllowed: boolean;
        defaultSelected: boolean;
        minimumRequired: CpPersonalField['minimumRequired'];
        isSystemManaged: boolean;
      }>;
    };
    integrations: {
      integrations: Array<{
        integrationKey: string;
        isAllowed: boolean;
        capabilities: Array<{
          capabilityKey: string;
          isAllowed: boolean;
        }>;
      }>;
    };
  };
};

export type ControlPlaneAccountDetail = {
  id: string;
  accountName: string;
  accountKey: string;
  cpStatus: CpStatus;
  cpRevision: number;
  createdAt: string;
  updatedAt: string;
  step2Progress: CpStep2Progress;
  access: CpAccessConfig;
  accountSettings: CpAccountSettingsConfig;
  moduleSettings: CpModuleSettingsConfig;
  personal: CpPersonalConfig;
  integrations: CpIntegrationsConfig;
  settingsHandoff: CpSettingsHandoffSnapshot;
};

export type CreateCpAccountInput = {
  accountName: string;
  accountKey: string;
};

export type SaveCpAccessInput = {
  loginMethods: CpAccessConfig['loginMethods'];
  mfaPolicy: CpAccessConfig['mfaPolicy'];
  signupPolicy: CpAccessConfig['signupPolicy'];
};

export type SaveCpAccountSettingsInput = {
  branding: CpAccountSettingsConfig['branding'];
  organizationStructure: CpAccountSettingsConfig['organizationStructure'];
  companyCalendar: CpAccountSettingsConfig['companyCalendar'];
};

export type SaveCpModuleSettingsInput = {
  modules: CpModuleSettingsConfig['modules'];
};

export type SaveCpPersonalInput = {
  families: Array<{
    familyKey: PersonalFamilyKey;
    isAllowed: boolean;
  }>;
  fields: Array<{
    fieldKey: string;
    isAllowed: boolean;
    defaultSelected: boolean;
  }>;
};

export type SaveCpIntegrationsInput = {
  integrations: Array<{
    integrationKey: string;
    isAllowed: boolean;
    capabilities: Array<{
      capabilityKey: string;
      isAllowed: boolean;
    }>;
  }>;
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
  publishedAt: string | null;
};

export type ControlPlaneAccountReview = {
  account: ControlPlaneAccountDetail;
  sections: CpReviewSection[];
  activationReadiness: CpActivationReadiness;
  provisioning: CpProvisioningResult;
};

export type PublishCpAccountInput = {
  targetStatus: Exclude<CpStatus, 'Draft'>;
};

export type UpdateCpAccountStatusInput = {
  targetStatus: Exclude<CpStatus, 'Draft'>;
};
