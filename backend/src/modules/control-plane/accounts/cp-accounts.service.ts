/**
 * backend/src/modules/control-plane/accounts/cp-accounts.service.ts
 *
 * WHY:
 * - Business orchestration for CP accounts, Step 2 group saves, and Phase 4
 *   Review & Publish.
 * - Owns uniqueness checks, group validation, progress-state updates,
 *   Activation Ready evaluation, and real tenant provisioning.
 *
 * RULES:
 * - All DB writes happen through the repo in a single transaction per request.
 * - cpRevision increments only on meaningful persisted CP allowance mutations.
 * - Publish must not fake later Settings cascade behavior.
 * - CP provisioning truth remains separate from tenant Settings truth.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { Logger } from '../../../shared/logger/logger';
import type {
  CreateCpAccountInput,
  PublishCpAccountInput,
  SaveCpAccessInput,
  SaveCpAccountSettingsInput,
  SaveCpIntegrationsInput,
  SaveCpModuleSettingsInput,
  SaveCpPersonalInput,
  UpdateCpAccountStatusInput,
} from './cp-accounts.schemas';
import type { CpAccountsRepo } from './dal/cp-accounts.repo';
import type {
  CpAccessConfigRow,
  CpAccountProvisioningRow,
  CpAccountRow,
  CpAccountSettingsConfigRow,
  CpIntegrationConfigRow,
  CpModuleConfigRow,
  CpPersonalFamilyConfigRow,
  CpPersonalFieldConfigRow,
  TenantProvisioningRow,
} from './dal/cp-accounts.query-sql';
import {
  findCpAccessConfigSql,
  findCpAccountByKeySql,
  findCpAccountProvisioningSql,
  findCpAccountSettingsConfigSql,
  findCpModuleConfigSql,
  findTenantProvisioningByIdSql,
  findTenantProvisioningByKeySql,
  listCpAccountsSql,
  listCpIntegrationConfigSql,
  listCpPersonalFamilyConfigSql,
  listCpPersonalFieldConfigSql,
} from './dal/cp-accounts.query-sql';
import { CpAccountErrors } from './cp-accounts.errors';
import {
  CP_SETUP_GROUPS,
  EDITABLE_PERSONAL_FIELD_CATALOG,
  GOOGLE_SSO_INTEGRATION_KEY,
  INTEGRATION_CATALOG,
  MICROSOFT_SSO_INTEGRATION_KEY,
  PERSONAL_FAMILY_DEFAULTS,
  PERSONAL_FAMILY_LABELS,
  PERSONAL_FIELD_CATALOG,
  REQUIRED_BASELINE_PERSONAL_FIELD_KEYS,
  type PersonalFamilyKey,
} from './cp-accounts.catalog';
import type {
  CpAccessConfig,
  CpAccountDetail,
  CpAccountListRow,
  CpAccountReview,
  CpAccountSettingsConfig,
  CpActivationReadiness,
  CpActivationReadinessCheck,
  CpIntegrationsConfig,
  CpIntegrationConfigItem,
  CpModuleSettingsConfig,
  CpPersonalConfig,
  CpPersonalFamily,
  CpPersonalField,
  CpProvisioningResult,
  CpReviewLine,
  CpReviewSection,
  CpStatus,
  CpStep2Progress,
} from './cp-accounts.types';

type AccountSnapshot = {
  account: CpAccountRow;
  accessRow: CpAccessConfigRow | undefined;
  accountSettingsRow: CpAccountSettingsConfigRow | undefined;
  moduleRow: CpModuleConfigRow | undefined;
  personalFamilyRows: CpPersonalFamilyConfigRow[];
  personalFieldRows: CpPersonalFieldConfigRow[];
  integrationRows: CpIntegrationConfigRow[];
  provisioningRow: CpAccountProvisioningRow | undefined;
  tenantRow: TenantProvisioningRow | undefined;
};

type ProvisionableTenantConfig = {
  isActive: boolean;
  publicSignupEnabled: boolean;
  adminInviteRequired: boolean;
  memberMfaRequired: boolean;
  allowedEmailDomains: string[];
  allowedSso: Array<'google' | 'microsoft'>;
};

function normalizeDomains(values: string[]): string[] {
  return Array.from(
    new Set(values.map((value) => value.trim().toLowerCase()).filter((value) => value.length > 0)),
  );
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`).join(',')}}`;
  }

  return JSON.stringify(value);
}

function normalizeStoredDomains(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return normalizeDomains(value.filter((entry): entry is string => typeof entry === 'string'));
}

function accessAllowanceChanged(
  snapshot: Pick<AccountSnapshot, 'account' | 'accessRow'>,
  next: SaveCpAccessInput,
): boolean {
  if (!snapshot.accessRow || !snapshot.account.access_configured) {
    return true;
  }

  const previousDomains = normalizeStoredDomains(snapshot.accessRow.allowed_domains);
  const nextDomains = normalizeDomains(next.signupPolicy.allowedDomains);

  return (
    snapshot.accessRow.login_password_allowed !== next.loginMethods.password ||
    snapshot.accessRow.login_google_allowed !== next.loginMethods.google ||
    snapshot.accessRow.login_microsoft_allowed !== next.loginMethods.microsoft ||
    snapshot.accessRow.admin_mfa_required !== next.mfaPolicy.adminRequired ||
    snapshot.accessRow.member_mfa_required !== next.mfaPolicy.memberRequired ||
    snapshot.accessRow.public_signup_allowed !== next.signupPolicy.publicSignup ||
    snapshot.accessRow.admin_invitations_allowed !== next.signupPolicy.adminInvitationsAllowed ||
    stableStringify(previousDomains) !== stableStringify(nextDomains)
  );
}

function buildStep2Progress(
  account: Pick<
    CpAccountRow,
    | 'access_configured'
    | 'account_settings_configured'
    | 'module_settings_configured'
    | 'integrations_configured'
  >,
): CpStep2Progress {
  const groups = CP_SETUP_GROUPS.map((group) => {
    const configured =
      group.slug === 'access-identity-security'
        ? account.access_configured
        : group.slug === 'account-settings'
          ? account.account_settings_configured
          : group.slug === 'module-settings'
            ? account.module_settings_configured
            : account.integrations_configured;

    return {
      slug: group.slug,
      title: group.title,
      isRequired: group.isRequired,
      configured,
    };
  });

  const configuredCount = groups.filter((group) => group.configured).length;
  const requiredGroups = groups.filter((group) => group.isRequired);
  const requiredConfiguredCount = requiredGroups.filter((group) => group.configured).length;

  return {
    configuredCount,
    totalCount: groups.length,
    requiredConfiguredCount,
    requiredTotalCount: requiredGroups.length,
    canContinueToReview: requiredConfiguredCount === requiredGroups.length,
    groups,
  };
}

function buildAccessConfig(
  row: CpAccessConfigRow | undefined,
  configured: boolean,
): CpAccessConfig {
  return {
    configured,
    loginMethods: {
      password: row?.login_password_allowed ?? true,
      google: row?.login_google_allowed ?? false,
      microsoft: row?.login_microsoft_allowed ?? false,
    },
    mfaPolicy: {
      adminRequired: row?.admin_mfa_required ?? true,
      memberRequired: row?.member_mfa_required ?? false,
    },
    signupPolicy: {
      publicSignup: row?.public_signup_allowed ?? false,
      adminInvitationsAllowed: row?.admin_invitations_allowed ?? true,
      allowedDomains: (row?.allowed_domains as string[] | undefined) ?? [],
    },
  };
}

function buildAccountSettingsConfig(
  row: CpAccountSettingsConfigRow | undefined,
  configured: boolean,
): CpAccountSettingsConfig {
  return {
    configured,
    branding: {
      logo: row?.branding_logo_allowed ?? true,
      menuColor: row?.branding_menu_color_allowed ?? true,
      fontColor: row?.branding_font_color_allowed ?? true,
      welcomeMessage: row?.branding_welcome_message_allowed ?? true,
    },
    organizationStructure: {
      employers: row?.org_employers_allowed ?? true,
      locations: row?.org_locations_allowed ?? true,
    },
    companyCalendar: {
      allowed: row?.company_calendar_allowed ?? true,
    },
  };
}

function buildModuleSettingsConfig(
  row: CpModuleConfigRow | undefined,
  configured: boolean,
): CpModuleSettingsConfig {
  return {
    configured,
    moduleDecisionsSaved: row?.decisions_saved ?? false,
    personalSubpageSaved: row?.personal_subpage_saved ?? false,
    modules: {
      personal: row?.personal_enabled ?? true,
      documents: row?.documents_enabled ?? false,
      benefits: row?.benefits_enabled ?? false,
      payments: row?.payments_enabled ?? false,
    },
  };
}

function buildPersonalConfig(
  familyRows: CpPersonalFamilyConfigRow[],
  fieldRows: CpPersonalFieldConfigRow[],
  saved: boolean,
): CpPersonalConfig {
  const familyMap = new Map(familyRows.map((row) => [row.family_key as PersonalFamilyKey, row]));
  const fieldMap = new Map(fieldRows.map((row) => [row.field_key, row]));

  const families: CpPersonalFamily[] = PERSONAL_FAMILY_DEFAULTS.map((family) => {
    const familyRow = familyMap.get(family.familyKey);
    const isAllowed = familyRow?.is_allowed ?? family.defaultAllowed;

    const fields: CpPersonalField[] = PERSONAL_FIELD_CATALOG.filter(
      (field) => field.familyKey === family.familyKey,
    ).map((field) => {
      const persisted = fieldMap.get(field.fieldKey);
      const effectiveAllowed = field.isSystemManaged
        ? true
        : (persisted?.is_allowed ?? (isAllowed ? field.defaultAllowed : false));
      const defaultSelected = field.isSystemManaged
        ? false
        : effectiveAllowed
          ? (persisted?.default_selected ?? field.defaultSelected)
          : false;
      const allowedLocked =
        field.isSystemManaged || REQUIRED_BASELINE_PERSONAL_FIELD_KEYS.has(field.fieldKey);

      return {
        familyKey: field.familyKey,
        fieldKey: field.fieldKey,
        label: field.label,
        notes: field.notes,
        isAllowed: effectiveAllowed,
        defaultSelected,
        minimumRequired: field.minimumRequired,
        isSystemManaged: field.isSystemManaged,
        allowedLocked,
      };
    });

    return {
      familyKey: family.familyKey,
      label: PERSONAL_FAMILY_LABELS[family.familyKey],
      isAllowed,
      allowedLocked: fields.some((field) => field.allowedLocked),
      fields,
    };
  });

  return { saved, families };
}

function buildIntegrationsConfig(
  rows: CpIntegrationConfigRow[],
  configured: boolean,
): CpIntegrationsConfig {
  const rowMap = new Map(rows.map((row) => [row.integration_key, row]));

  const integrations: CpIntegrationConfigItem[] = INTEGRATION_CATALOG.map((integration) => {
    const row = rowMap.get(integration.integrationKey);

    return {
      integrationKey: integration.integrationKey,
      label: integration.label,
      isAllowed: row?.is_allowed ?? integration.defaultAllowed,
      capabilities: integration.capabilities.map((capability) => {
        let isAllowed = capability.defaultAllowed;

        if (row) {
          if (capability.capabilityKey.endsWith('.data_sync')) {
            isAllowed = row.data_sync_allowed ?? capability.defaultAllowed;
          } else if (capability.capabilityKey.endsWith('.import_enabled')) {
            isAllowed = row.import_enabled_allowed ?? capability.defaultAllowed;
          } else if (capability.capabilityKey.endsWith('.import_rules')) {
            isAllowed = row.import_rules_allowed ?? capability.defaultAllowed;
          } else if (capability.capabilityKey.endsWith('.field_mapping')) {
            isAllowed = row.field_mapping_allowed ?? capability.defaultAllowed;
          } else if (capability.capabilityKey.endsWith('.payments_surface')) {
            isAllowed = row.payments_surface_allowed ?? capability.defaultAllowed;
          }
        }

        return {
          capabilityKey: capability.capabilityKey,
          label: capability.label,
          isAllowed,
        };
      }),
    };
  });

  return { configured, integrations };
}

function integrationAllowed(rows: CpIntegrationConfigRow[], integrationKey: string): boolean {
  return rows.find((row) => row.integration_key === integrationKey)?.is_allowed ?? false;
}

function moduleGroupConfigured(row: CpModuleConfigRow | undefined): boolean {
  if (!row) return false;
  if (!row.decisions_saved) return false;
  if (!row.personal_enabled) return true;
  return row.personal_subpage_saved;
}

async function loadAccountSnapshot(db: DbExecutor, accountKey: string): Promise<AccountSnapshot> {
  const account = await findCpAccountByKeySql(db, accountKey);

  if (!account) {
    throw CpAccountErrors.notFound(accountKey);
  }

  const [
    accessRow,
    accountSettingsRow,
    moduleRow,
    personalFamilyRows,
    personalFieldRows,
    integrationRows,
    provisioningRow,
  ] = await Promise.all([
    findCpAccessConfigSql(db, account.id),
    findCpAccountSettingsConfigSql(db, account.id),
    findCpModuleConfigSql(db, account.id),
    listCpPersonalFamilyConfigSql(db, account.id),
    listCpPersonalFieldConfigSql(db, account.id),
    listCpIntegrationConfigSql(db, account.id),
    findCpAccountProvisioningSql(db, account.id),
  ]);

  const tenantRow = provisioningRow
    ? await findTenantProvisioningByIdSql(db, provisioningRow.tenant_id)
    : undefined;

  return {
    account,
    accessRow,
    accountSettingsRow,
    moduleRow,
    personalFamilyRows,
    personalFieldRows,
    integrationRows,
    provisioningRow,
    tenantRow,
  };
}

function snapshotToAccountDetail(snapshot: AccountSnapshot): CpAccountDetail {
  const moduleConfigured = moduleGroupConfigured(snapshot.moduleRow);
  const accountWithProgress: CpAccountRow = {
    ...snapshot.account,
    module_settings_configured: moduleConfigured,
  };

  return {
    id: snapshot.account.id,
    accountName: snapshot.account.account_name,
    accountKey: snapshot.account.account_key,
    cpStatus: snapshot.account.cp_status as CpStatus,
    cpRevision: snapshot.account.cp_revision,
    createdAt: snapshot.account.created_at,
    updatedAt: snapshot.account.updated_at,
    step2Progress: buildStep2Progress(accountWithProgress),
    access: buildAccessConfig(snapshot.accessRow, snapshot.account.access_configured),
    accountSettings: buildAccountSettingsConfig(
      snapshot.accountSettingsRow,
      snapshot.account.account_settings_configured,
    ),
    moduleSettings: buildModuleSettingsConfig(snapshot.moduleRow, moduleConfigured),
    personal: buildPersonalConfig(
      snapshot.personalFamilyRows,
      snapshot.personalFieldRows,
      snapshot.moduleRow?.personal_subpage_saved ?? false,
    ),
    integrations: buildIntegrationsConfig(
      snapshot.integrationRows,
      snapshot.account.integrations_configured,
    ),
  };
}

function yesNo(value: boolean): string {
  return value ? 'Yes' : 'No';
}

function commaList(values: string[]): string {
  return values.length ? values.join(', ') : 'None';
}

function enabledLabels(values: Array<[string, boolean]>): string {
  const enabled = values.filter(([, on]) => on).map(([label]) => label);
  return enabled.length ? enabled.join(', ') : 'None selected';
}

function buildReviewSections(account: CpAccountDetail): CpReviewSection[] {
  const allowedBranding = Object.entries(account.accountSettings.branding)
    .filter(([, value]) => value)
    .map(([key]) => {
      if (key === 'menuColor') return 'Menu Color';
      if (key === 'fontColor') return 'Font Color';
      if (key === 'welcomeMessage') return 'Welcome Message';
      return 'Logo';
    });
  const allowedOrg = Object.entries(account.accountSettings.organizationStructure)
    .filter(([, value]) => value)
    .map(([key]) => (key === 'employers' ? 'Employers' : 'Locations'));

  const personalAllowedFamilies = account.personal.families.filter((family) => family.isAllowed);
  const personalAllowedFields = personalAllowedFamilies.flatMap((family) =>
    family.fields.filter((field) => field.isAllowed),
  );
  const personalDefaultSelected = personalAllowedFields.filter((field) => field.defaultSelected);

  const integrationLines: CpReviewLine[] = account.integrations.integrations.map((integration) => ({
    label: integration.label,
    value: integration.isAllowed
      ? integration.capabilities.length > 0
        ? `Allowed (${integration.capabilities.filter((capability) => capability.isAllowed).length} capabilities enabled)`
        : 'Allowed'
      : 'Not allowed',
  }));

  return [
    {
      key: 'identity',
      title: 'Account Identity',
      lines: [
        { label: 'Account Name', value: account.accountName },
        { label: 'Account Key', value: account.accountKey },
        { label: 'Current CP Status', value: account.cpStatus },
        { label: 'Current cpRevision', value: String(account.cpRevision) },
      ],
    },
    {
      key: 'access',
      title: 'Access, Identity & Security',
      lines: [
        {
          label: 'Configured',
          value: yesNo(account.access.configured),
        },
        {
          label: 'Login Methods',
          value: enabledLabels([
            ['Username & Password', account.access.loginMethods.password],
            ['Google SSO', account.access.loginMethods.google],
            ['Microsoft SSO', account.access.loginMethods.microsoft],
          ]),
        },
        { label: 'Admin MFA', value: account.access.mfaPolicy.adminRequired ? 'Required' : 'Off' },
        {
          label: 'Member MFA',
          value: account.access.mfaPolicy.memberRequired ? 'Required' : 'Optional / Off',
        },
        {
          label: 'Public Signup',
          value: account.access.signupPolicy.publicSignup ? 'Enabled' : 'Disabled',
        },
        {
          label: 'Admin Invitations Allowed',
          value: account.access.signupPolicy.adminInvitationsAllowed ? 'Yes' : 'No',
        },
        {
          label: 'Allowed Domains',
          value: commaList(account.access.signupPolicy.allowedDomains),
        },
      ],
    },
    {
      key: 'accountSettings',
      title: 'Account Settings',
      lines: [
        { label: 'Configured', value: yesNo(account.accountSettings.configured) },
        { label: 'Branding Surfaces Allowed', value: commaList(allowedBranding) },
        { label: 'Organization Structure Allowed', value: commaList(allowedOrg) },
        {
          label: 'Company Calendar Allowed',
          value: account.accountSettings.companyCalendar.allowed ? 'Yes' : 'No',
        },
      ],
    },
    {
      key: 'moduleSettings',
      title: 'Module Settings',
      lines: [
        { label: 'Configured', value: yesNo(account.moduleSettings.configured) },
        {
          label: 'Enabled Modules',
          value: enabledLabels([
            ['Personal', account.moduleSettings.modules.personal],
            ['Documents', account.moduleSettings.modules.documents],
            ['Benefits', account.moduleSettings.modules.benefits],
            ['Payments', account.moduleSettings.modules.payments],
          ]),
        },
        {
          label: 'Personal Catalog Saved',
          value: account.moduleSettings.modules.personal
            ? yesNo(account.moduleSettings.personalSubpageSaved)
            : 'Not applicable',
        },
      ],
    },
    {
      key: 'personalAllowances',
      title: 'Personal Allowances',
      lines: account.moduleSettings.modules.personal
        ? [
            {
              label: 'Personal Saved',
              value: yesNo(account.personal.saved),
            },
            {
              label: 'Allowed Families',
              value: commaList(personalAllowedFamilies.map((family) => family.label)),
            },
            {
              label: 'Allowed Fields',
              value: `${personalAllowedFields.length}`,
            },
            {
              label: 'Default Selected Fields',
              value: `${personalDefaultSelected.length}`,
            },
          ]
        : [{ label: 'Personal Module', value: 'Not enabled' }],
    },
    {
      key: 'integrations',
      title: 'Integrations & Marketplace',
      lines: [
        { label: 'Configured', value: yesNo(account.integrations.configured) },
        ...integrationLines,
      ],
    },
  ];
}

function evaluateActivationReadiness(account: CpAccountDetail): CpActivationReadiness {
  const googleAllowed = account.integrations.integrations.find(
    (integration) => integration.integrationKey === GOOGLE_SSO_INTEGRATION_KEY,
  )?.isAllowed;
  const microsoftAllowed = account.integrations.integrations.find(
    (integration) => integration.integrationKey === MICROSOFT_SSO_INTEGRATION_KEY,
  )?.isAllowed;
  const hasLoginMethod = Object.values(account.access.loginMethods).some(Boolean);

  const checks: CpActivationReadinessCheck[] = [
    {
      code: 'ACCOUNT_IDENTITY_PRESENT',
      label: 'Account Name + Account Key exist',
      passed: Boolean(account.accountName && account.accountKey),
      detail:
        account.accountName && account.accountKey
          ? 'Basic account identity has been created.'
          : 'Create the basic account identity before publishing Active.',
    },
    {
      code: 'ACCESS_DECISIONS_MADE',
      label: 'Access, Identity & Security decisions made',
      passed: account.access.configured,
      detail: account.access.configured
        ? 'Access group has been explicitly saved.'
        : 'Save the Access, Identity & Security group first.',
    },
    {
      code: 'LOGIN_METHOD_SELECTED',
      label: 'At least one login method selected',
      passed: hasLoginMethod,
      detail: hasLoginMethod
        ? 'At least one login method is enabled.'
        : 'Select at least one login method before publishing Active.',
    },
    {
      code: 'ACCOUNT_SETTINGS_DECISIONS_MADE',
      label: 'Account Settings decisions made',
      passed: account.accountSettings.configured,
      detail: account.accountSettings.configured
        ? 'Account Settings has been explicitly saved.'
        : 'Save the Account Settings group first.',
    },
    {
      code: 'MODULE_DECISIONS_MADE',
      label: 'Module decisions made',
      passed: account.moduleSettings.moduleDecisionsSaved,
      detail: account.moduleSettings.moduleDecisionsSaved
        ? 'Module choices have been explicitly saved.'
        : 'Save the Module Settings group first.',
    },
    {
      code: 'PERSONAL_CATALOG_DEFINED',
      label: 'Enabled module field catalog/config boundary is defined',
      passed: !account.moduleSettings.modules.personal || account.personal.saved,
      detail: !account.moduleSettings.modules.personal
        ? 'Personal is not enabled, so no Personal catalog save is required.'
        : account.personal.saved
          ? 'Personal field catalog has been explicitly saved.'
          : 'Save the Personal CP sub-page because Personal is enabled.',
    },
    {
      code: 'INTEGRATION_DECISIONS_RELEVANT',
      label: 'Integration decisions made where relevant',
      passed:
        (!account.access.loginMethods.google || Boolean(googleAllowed)) &&
        (!account.access.loginMethods.microsoft || Boolean(microsoftAllowed)),
      detail:
        !account.access.loginMethods.google && !account.access.loginMethods.microsoft
          ? 'No SSO login dependency requires an integration allowance.'
          : !account.access.loginMethods.google || Boolean(googleAllowed)
            ? !account.access.loginMethods.microsoft || Boolean(microsoftAllowed)
              ? 'Required SSO integration allowances exist for the enabled login methods.'
              : 'Microsoft login is enabled but Microsoft SSO Integration is not allowed.'
            : 'Google login is enabled but Google SSO Integration is not allowed.',
    },
  ];

  const blockingReasons = checks.filter((check) => !check.passed).map((check) => check.detail);

  return {
    isReady: blockingReasons.length === 0,
    checks,
    blockingReasons,
  };
}

function buildProvisioningResult(snapshot: AccountSnapshot): CpProvisioningResult {
  const provisioning = snapshot.provisioningRow;
  const tenant = snapshot.tenantRow;

  if (!provisioning || !tenant) {
    return {
      isProvisioned: false,
      tenantId: null,
      tenantKey: null,
      tenantName: null,
      tenantState: 'NOT_PROVISIONED',
      publishedAt: null,
    };
  }

  return {
    isProvisioned: true,
    tenantId: tenant.id,
    tenantKey: tenant.key,
    tenantName: tenant.name,
    tenantState: tenant.is_active ? 'ACTIVE' : 'DISABLED',
    publishedAt: provisioning.published_at,
  };
}

function snapshotToReview(snapshot: AccountSnapshot): CpAccountReview {
  const account = snapshotToAccountDetail(snapshot);

  return {
    account,
    sections: buildReviewSections(account),
    activationReadiness: evaluateActivationReadiness(account),
    provisioning: buildProvisioningResult(snapshot),
  };
}

function deriveProvisionableTenantConfig(
  account: CpAccountDetail,
  targetStatus: 'Active' | 'Disabled',
): ProvisionableTenantConfig {
  const googleAllowed = account.integrations.integrations.find(
    (integration) => integration.integrationKey === GOOGLE_SSO_INTEGRATION_KEY,
  )?.isAllowed;
  const microsoftAllowed = account.integrations.integrations.find(
    (integration) => integration.integrationKey === MICROSOFT_SSO_INTEGRATION_KEY,
  )?.isAllowed;

  const allowedSso: Array<'google' | 'microsoft'> = [];

  if (account.access.configured && account.access.loginMethods.google && googleAllowed) {
    allowedSso.push('google');
  }
  if (account.access.configured && account.access.loginMethods.microsoft && microsoftAllowed) {
    allowedSso.push('microsoft');
  }

  const publicSignupEnabled = account.access.configured
    ? account.access.signupPolicy.publicSignup
    : false;
  const adminInviteRequired = account.access.configured
    ? !account.access.signupPolicy.publicSignup &&
      account.access.signupPolicy.adminInvitationsAllowed
    : false;

  return {
    isActive: targetStatus === 'Active',
    publicSignupEnabled,
    adminInviteRequired,
    memberMfaRequired: account.access.configured ? account.access.mfaPolicy.memberRequired : false,
    allowedEmailDomains: account.access.configured
      ? account.access.signupPolicy.allowedDomains
      : [],
    allowedSso,
  };
}

export class CpAccountsService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      logger: Logger;
      cpAccountsRepo: CpAccountsRepo;
    },
  ) {}

  private async applyProvisioningStatus(
    trx: DbExecutor,
    snapshot: AccountSnapshot,
    review: CpAccountReview,
    targetStatus: 'Active' | 'Disabled',
    logEvent: 'cp.accounts.published' | 'cp.accounts.status_toggled',
  ): Promise<void> {
    const repo = this.deps.cpAccountsRepo.withDb(trx);
    const existingTenantByKey = await findTenantProvisioningByKeySql(
      trx,
      snapshot.account.account_key,
    );

    if (existingTenantByKey && existingTenantByKey.id !== snapshot.provisioningRow?.tenant_id) {
      throw CpAccountErrors.tenantProvisioningConflict(snapshot.account.account_key);
    }

    const tenantConfig = deriveProvisionableTenantConfig(review.account, targetStatus);
    const publishedAt = new Date();

    let tenantId = snapshot.provisioningRow?.tenant_id ?? null;

    if (tenantId) {
      await repo.updateTenantProvisioning({
        tenantId,
        tenantName: snapshot.account.account_name,
        isActive: tenantConfig.isActive,
        publicSignupEnabled: tenantConfig.publicSignupEnabled,
        adminInviteRequired: tenantConfig.adminInviteRequired,
        memberMfaRequired: tenantConfig.memberMfaRequired,
        allowedEmailDomains: tenantConfig.allowedEmailDomains,
        allowedSso: tenantConfig.allowedSso,
      });
    } else if (existingTenantByKey) {
      tenantId = existingTenantByKey.id;
      await repo.updateTenantProvisioning({
        tenantId,
        tenantName: snapshot.account.account_name,
        isActive: tenantConfig.isActive,
        publicSignupEnabled: tenantConfig.publicSignupEnabled,
        adminInviteRequired: tenantConfig.adminInviteRequired,
        memberMfaRequired: tenantConfig.memberMfaRequired,
        allowedEmailDomains: tenantConfig.allowedEmailDomains,
        allowedSso: tenantConfig.allowedSso,
      });
    } else {
      const inserted = await repo.insertTenantProvisioning({
        tenantKey: snapshot.account.account_key,
        tenantName: snapshot.account.account_name,
        isActive: tenantConfig.isActive,
        publicSignupEnabled: tenantConfig.publicSignupEnabled,
        adminInviteRequired: tenantConfig.adminInviteRequired,
        memberMfaRequired: tenantConfig.memberMfaRequired,
        allowedEmailDomains: tenantConfig.allowedEmailDomains,
        allowedSso: tenantConfig.allowedSso,
      });
      tenantId = inserted.tenantId;
    }

    await repo.upsertProvisioningResult({
      accountId: snapshot.account.id,
      tenantId,
      cpStatus: targetStatus,
      publishedAt,
    });

    await repo.updateAccountStatus({
      accountId: snapshot.account.id,
      cpStatus: targetStatus,
    });

    this.deps.logger.info(logEvent, {
      event: logEvent,
      accountId: snapshot.account.id,
      accountKey: snapshot.account.account_key,
      targetStatus,
      tenantId,
    });
  }

  async createAccount(input: CreateCpAccountInput): Promise<CpAccountDetail> {
    const existing = await findCpAccountByKeySql(this.deps.db, input.accountKey);

    if (existing) {
      throw CpAccountErrors.accountKeyConflict(input.accountKey);
    }

    const { id, accountKey } = await this.deps.cpAccountsRepo.insertAccount({
      accountName: input.accountName,
      accountKey: input.accountKey,
    });

    this.deps.logger.info('cp.accounts.created', {
      event: 'cp.accounts.created',
      accountKey,
      id,
    });

    return this.getAccount(accountKey);
  }

  async getAccount(accountKey: string): Promise<CpAccountDetail> {
    const snapshot = await loadAccountSnapshot(this.deps.db, accountKey);
    return snapshotToAccountDetail(snapshot);
  }

  async getReview(accountKey: string): Promise<CpAccountReview> {
    const snapshot = await loadAccountSnapshot(this.deps.db, accountKey);
    return snapshotToReview(snapshot);
  }

  async listAccounts(): Promise<CpAccountListRow[]> {
    const rows = await listCpAccountsSql(this.deps.db);

    return rows.map((row) => ({
      id: row.id,
      accountName: row.account_name,
      accountKey: row.account_key,
      cpStatus: row.cp_status as CpStatus,
      cpRevision: row.cp_revision,
      step2Progress: buildStep2Progress(row),
    }));
  }

  async saveAccess(accountKey: string, input: SaveCpAccessInput): Promise<CpAccountDetail> {
    const normalized: SaveCpAccessInput = {
      loginMethods: {
        password: input.loginMethods.password,
        google: input.loginMethods.google,
        microsoft: input.loginMethods.microsoft,
      },
      mfaPolicy: {
        adminRequired: true,
        memberRequired: input.mfaPolicy.memberRequired,
      },
      signupPolicy: {
        publicSignup: input.signupPolicy.publicSignup,
        adminInvitationsAllowed: input.signupPolicy.adminInvitationsAllowed,
        allowedDomains: normalizeDomains(input.signupPolicy.allowedDomains),
      },
    };

    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.cpAccountsRepo.withDb(trx);
      const snapshot = await loadAccountSnapshot(trx, accountKey);

      if (
        normalized.loginMethods.google &&
        !integrationAllowed(snapshot.integrationRows, GOOGLE_SSO_INTEGRATION_KEY)
      ) {
        throw CpAccountErrors.accessDependencyConflict(
          'Google login method requires the Google SSO integration allowance to be saved first.',
          { integrationKey: GOOGLE_SSO_INTEGRATION_KEY },
        );
      }

      if (
        normalized.loginMethods.microsoft &&
        !integrationAllowed(snapshot.integrationRows, MICROSOFT_SSO_INTEGRATION_KEY)
      ) {
        throw CpAccountErrors.accessDependencyConflict(
          'Microsoft login method requires the Microsoft SSO integration allowance to be saved first.',
          { integrationKey: MICROSOFT_SSO_INTEGRATION_KEY },
        );
      }

      const changed = accessAllowanceChanged(snapshot, normalized);

      await repo.upsertAccessConfig({
        accountId: snapshot.account.id,
        loginPasswordAllowed: normalized.loginMethods.password,
        loginGoogleAllowed: normalized.loginMethods.google,
        loginMicrosoftAllowed: normalized.loginMethods.microsoft,
        adminMfaRequired: normalized.mfaPolicy.adminRequired,
        memberMfaRequired: normalized.mfaPolicy.memberRequired,
        publicSignupAllowed: normalized.signupPolicy.publicSignup,
        adminInvitationsAllowed: normalized.signupPolicy.adminInvitationsAllowed,
        allowedDomains: normalized.signupPolicy.allowedDomains,
      });

      await repo.updateAccountProgressAndRevision({
        accountId: snapshot.account.id,
        progressPatch: { accessConfigured: true },
        incrementRevision: changed,
      });

      return snapshotToAccountDetail(await loadAccountSnapshot(trx, accountKey));
    });
  }

  async saveAccountSettings(
    accountKey: string,
    input: SaveCpAccountSettingsInput,
  ): Promise<CpAccountDetail> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.cpAccountsRepo.withDb(trx);
      const snapshot = await loadAccountSnapshot(trx, accountKey);

      const previous = buildAccountSettingsConfig(
        snapshot.accountSettingsRow,
        snapshot.account.account_settings_configured,
      );
      const next: CpAccountSettingsConfig = {
        configured: true,
        branding: input.branding,
        organizationStructure: input.organizationStructure,
        companyCalendar: input.companyCalendar,
      };
      const changed = stableStringify(previous) !== stableStringify(next);

      await repo.upsertAccountSettingsConfig({
        accountId: snapshot.account.id,
        brandingLogoAllowed: input.branding.logo,
        brandingMenuColorAllowed: input.branding.menuColor,
        brandingFontColorAllowed: input.branding.fontColor,
        brandingWelcomeMessageAllowed: input.branding.welcomeMessage,
        orgEmployersAllowed: input.organizationStructure.employers,
        orgLocationsAllowed: input.organizationStructure.locations,
        companyCalendarAllowed: input.companyCalendar.allowed,
      });

      await repo.updateAccountProgressAndRevision({
        accountId: snapshot.account.id,
        progressPatch: { accountSettingsConfigured: true },
        incrementRevision: changed,
      });

      return snapshotToAccountDetail(await loadAccountSnapshot(trx, accountKey));
    });
  }

  async saveModuleSettings(
    accountKey: string,
    input: SaveCpModuleSettingsInput,
  ): Promise<CpAccountDetail> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.cpAccountsRepo.withDb(trx);
      const snapshot = await loadAccountSnapshot(trx, accountKey);
      const previous = buildModuleSettingsConfig(
        snapshot.moduleRow,
        moduleGroupConfigured(snapshot.moduleRow),
      );

      const existingPersonalSubpageSaved = input.modules.personal
        ? (snapshot.moduleRow?.personal_subpage_saved ?? false)
        : false;

      const nextConfigured = input.modules.personal ? existingPersonalSubpageSaved : true;
      const next: CpModuleSettingsConfig = {
        configured: nextConfigured,
        moduleDecisionsSaved: true,
        personalSubpageSaved: existingPersonalSubpageSaved,
        modules: input.modules,
      };
      const changed = stableStringify(previous) !== stableStringify(next);

      await repo.upsertModuleConfig({
        accountId: snapshot.account.id,
        personalEnabled: input.modules.personal,
        documentsEnabled: input.modules.documents,
        benefitsEnabled: input.modules.benefits,
        paymentsEnabled: input.modules.payments,
        decisionsSaved: true,
        personalSubpageSaved: existingPersonalSubpageSaved,
      });

      await repo.updateAccountProgressAndRevision({
        accountId: snapshot.account.id,
        progressPatch: { moduleSettingsConfigured: nextConfigured },
        incrementRevision: changed,
      });

      return snapshotToAccountDetail(await loadAccountSnapshot(trx, accountKey));
    });
  }

  async savePersonal(accountKey: string, input: SaveCpPersonalInput): Promise<CpAccountDetail> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.cpAccountsRepo.withDb(trx);
      const snapshot = await loadAccountSnapshot(trx, accountKey);
      const moduleRow = snapshot.moduleRow;

      if (!moduleRow?.personal_enabled) {
        throw CpAccountErrors.personalValidation(
          'Personal must be enabled in Module Settings before the Personal CP sub-page can be saved.',
        );
      }

      const expectedFamilyKeys = new Set(
        PERSONAL_FAMILY_DEFAULTS.map((family) => family.familyKey),
      );
      const providedFamilyKeys = new Set(input.families.map((family) => family.familyKey));

      if (expectedFamilyKeys.size !== providedFamilyKeys.size) {
        throw CpAccountErrors.personalValidation(
          'Personal save must include the full family set for the current CP catalog.',
        );
      }

      for (const familyKey of expectedFamilyKeys) {
        if (!providedFamilyKeys.has(familyKey)) {
          throw CpAccountErrors.personalValidation(
            'Personal save is missing one or more family rows.',
          );
        }
      }

      const expectedFieldKeys = new Set(
        EDITABLE_PERSONAL_FIELD_CATALOG.map((field) => field.fieldKey),
      );
      const providedFieldKeys = new Set(input.fields.map((field) => field.fieldKey));

      if (expectedFieldKeys.size !== providedFieldKeys.size) {
        throw CpAccountErrors.personalValidation(
          'Personal save must include the full editable field set for the current CP catalog.',
        );
      }

      for (const fieldKey of expectedFieldKeys) {
        if (!providedFieldKeys.has(fieldKey)) {
          throw CpAccountErrors.personalValidation(
            'Personal save is missing one or more field rows.',
          );
        }
      }

      const familyAllowedMap = new Map<PersonalFamilyKey, boolean>(
        input.families.map((family) => [family.familyKey as PersonalFamilyKey, family.isAllowed]),
      );

      const normalizedFamilies = PERSONAL_FAMILY_DEFAULTS.map((family) => ({
        familyKey: family.familyKey,
        isAllowed: familyAllowedMap.get(family.familyKey) ?? family.defaultAllowed,
      }));

      const normalizedFields = EDITABLE_PERSONAL_FIELD_CATALOG.map((catalogField) => {
        const payloadField = input.fields.find((field) => field.fieldKey === catalogField.fieldKey);

        if (!payloadField) {
          throw CpAccountErrors.personalValidation(
            'Personal save is missing one or more field rows.',
          );
        }

        const familyAllowed = familyAllowedMap.get(catalogField.familyKey) ?? true;
        const requiredBaseline = REQUIRED_BASELINE_PERSONAL_FIELD_KEYS.has(catalogField.fieldKey);
        const isAllowed = requiredBaseline ? true : familyAllowed ? payloadField.isAllowed : false;
        const defaultSelected = isAllowed ? payloadField.defaultSelected : false;

        if (payloadField.defaultSelected && !isAllowed) {
          throw CpAccountErrors.personalValidation(
            'Default Selected is only valid when Allowed is true.',
            { fieldKey: catalogField.fieldKey },
          );
        }

        return {
          familyKey: catalogField.familyKey,
          fieldKey: catalogField.fieldKey,
          isAllowed,
          defaultSelected,
        };
      });

      const previous = buildPersonalConfig(
        snapshot.personalFamilyRows,
        snapshot.personalFieldRows,
        snapshot.moduleRow?.personal_subpage_saved ?? false,
      );
      const next = buildPersonalConfig(
        normalizedFamilies.map((family) => ({
          account_id: snapshot.account.id,
          family_key: family.familyKey,
          is_allowed: family.isAllowed,
          created_at: new Date(),
          updated_at: new Date(),
          id: 'preview',
        })),
        normalizedFields.map((field) => ({
          account_id: snapshot.account.id,
          family_key: field.familyKey,
          field_key: field.fieldKey,
          is_allowed: field.isAllowed,
          default_selected: field.defaultSelected,
          created_at: new Date(),
          updated_at: new Date(),
          id: 'preview',
        })),
        true,
      );
      const changed = stableStringify(previous) !== stableStringify(next);

      await repo.replacePersonalConfig({
        accountId: snapshot.account.id,
        families: normalizedFamilies,
        fields: normalizedFields,
      });

      const nextModuleConfigured = Boolean(moduleRow?.decisions_saved);

      await repo.upsertModuleConfig({
        accountId: snapshot.account.id,
        personalEnabled: true,
        documentsEnabled: moduleRow?.documents_enabled ?? false,
        benefitsEnabled: moduleRow?.benefits_enabled ?? false,
        paymentsEnabled: moduleRow?.payments_enabled ?? false,
        decisionsSaved: moduleRow?.decisions_saved ?? false,
        personalSubpageSaved: true,
      });

      await repo.updateAccountProgressAndRevision({
        accountId: snapshot.account.id,
        progressPatch: { moduleSettingsConfigured: nextModuleConfigured },
        incrementRevision: changed,
      });

      return snapshotToAccountDetail(await loadAccountSnapshot(trx, accountKey));
    });
  }

  async saveIntegrations(
    accountKey: string,
    input: SaveCpIntegrationsInput,
  ): Promise<CpAccountDetail> {
    return this.deps.db.transaction().execute(async (trx) => {
      const repo = this.deps.cpAccountsRepo.withDb(trx);
      const snapshot = await loadAccountSnapshot(trx, accountKey);
      const access = buildAccessConfig(snapshot.accessRow, snapshot.account.access_configured);

      if (input.integrations.length !== INTEGRATION_CATALOG.length) {
        throw CpAccountErrors.personalValidation(
          'Integrations save must include the full integration set for the current CP catalog.',
        );
      }

      const integrationRows = INTEGRATION_CATALOG.map((catalogIntegration) => {
        const payload = input.integrations.find(
          (integration) => integration.integrationKey === catalogIntegration.integrationKey,
        );

        if (!payload) {
          throw CpAccountErrors.personalValidation(
            'Integrations save must include the full integration set for the current CP catalog.',
          );
        }

        const capabilityMap = new Map(
          payload.capabilities.map((capability) => [
            capability.capabilityKey,
            capability.isAllowed,
          ]),
        );

        return {
          integrationKey: catalogIntegration.integrationKey,
          isAllowed: payload.isAllowed,
          dataSyncAllowed:
            capabilityMap.get(`${catalogIntegration.integrationKey}.data_sync`) ?? null,
          importEnabledAllowed:
            capabilityMap.get(`${catalogIntegration.integrationKey}.import_enabled`) ?? null,
          importRulesAllowed:
            capabilityMap.get(`${catalogIntegration.integrationKey}.import_rules`) ?? null,
          fieldMappingAllowed:
            capabilityMap.get(`${catalogIntegration.integrationKey}.field_mapping`) ?? null,
          paymentsSurfaceAllowed:
            capabilityMap.get(`${catalogIntegration.integrationKey}.payments_surface`) ?? null,
        };
      });

      const googleIntegration = integrationRows.find(
        (row) => row.integrationKey === GOOGLE_SSO_INTEGRATION_KEY,
      )?.isAllowed;
      const microsoftIntegration = integrationRows.find(
        (row) => row.integrationKey === MICROSOFT_SSO_INTEGRATION_KEY,
      )?.isAllowed;

      if (access.loginMethods.google && !googleIntegration) {
        throw CpAccountErrors.integrationsDependencyConflict(
          'Google SSO integration cannot be disabled while Google login method remains enabled in Access, Identity & Security.',
          { integrationKey: GOOGLE_SSO_INTEGRATION_KEY },
        );
      }

      if (access.loginMethods.microsoft && !microsoftIntegration) {
        throw CpAccountErrors.integrationsDependencyConflict(
          'Microsoft SSO integration cannot be disabled while Microsoft login method remains enabled in Access, Identity & Security.',
          { integrationKey: MICROSOFT_SSO_INTEGRATION_KEY },
        );
      }

      const previous = buildIntegrationsConfig(
        snapshot.integrationRows,
        snapshot.account.integrations_configured,
      );
      const next = buildIntegrationsConfig(
        integrationRows.map((row) => ({
          account_id: snapshot.account.id,
          created_at: new Date(),
          data_sync_allowed: row.dataSyncAllowed,
          field_mapping_allowed: row.fieldMappingAllowed,
          id: 'preview',
          import_enabled_allowed: row.importEnabledAllowed,
          import_rules_allowed: row.importRulesAllowed,
          integration_key: row.integrationKey,
          is_allowed: row.isAllowed,
          payments_surface_allowed: row.paymentsSurfaceAllowed,
          updated_at: new Date(),
        })),
        true,
      );
      const changed = stableStringify(previous) !== stableStringify(next);

      await repo.replaceIntegrationConfig({
        accountId: snapshot.account.id,
        rows: integrationRows,
      });

      await repo.updateAccountProgressAndRevision({
        accountId: snapshot.account.id,
        progressPatch: { integrationsConfigured: true },
        incrementRevision: changed,
      });

      return snapshotToAccountDetail(await loadAccountSnapshot(trx, accountKey));
    });
  }

  async updateStatus(
    accountKey: string,
    input: UpdateCpAccountStatusInput,
  ): Promise<CpAccountDetail> {
    return this.deps.db.transaction().execute(async (trx) => {
      const snapshot = await loadAccountSnapshot(trx, accountKey);

      if (
        snapshot.account.cp_status === 'Draft' ||
        !snapshot.provisioningRow ||
        !snapshot.tenantRow
      ) {
        throw CpAccountErrors.statusToggleUnavailable(accountKey);
      }

      if (snapshot.account.cp_status === input.targetStatus) {
        return snapshotToAccountDetail(snapshot);
      }

      const review = snapshotToReview(snapshot);

      if (input.targetStatus === 'Active' && !review.activationReadiness.isReady) {
        throw CpAccountErrors.activationReadyConflict(review.activationReadiness.blockingReasons);
      }

      await this.applyProvisioningStatus(
        trx,
        snapshot,
        review,
        input.targetStatus,
        'cp.accounts.status_toggled',
      );

      return snapshotToAccountDetail(await loadAccountSnapshot(trx, accountKey));
    });
  }

  async publishAccount(accountKey: string, input: PublishCpAccountInput): Promise<CpAccountReview> {
    return this.deps.db.transaction().execute(async (trx) => {
      const snapshot = await loadAccountSnapshot(trx, accountKey);
      const review = snapshotToReview(snapshot);

      if (input.targetStatus === 'Active' && !review.activationReadiness.isReady) {
        throw CpAccountErrors.activationReadyConflict(review.activationReadiness.blockingReasons);
      }

      await this.applyProvisioningStatus(
        trx,
        snapshot,
        review,
        input.targetStatus,
        'cp.accounts.published',
      );

      return snapshotToReview(await loadAccountSnapshot(trx, accountKey));
    });
  }
}
