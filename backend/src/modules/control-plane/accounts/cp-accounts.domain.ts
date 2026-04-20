/**
 * backend/src/modules/control-plane/accounts/cp-accounts.domain.ts
 *
 * WHY:
 * - Holds pure CP account-domain helpers that were previously embedded inside
 *   CpAccountsService.
 * - Keeps snapshot mapping, review composition, allowance normalization, and
 *   activation-readiness rules together without mixing them into mutation
 *   orchestration.
 *
 * RULES:
 * - No logging, no AuditWriter usage, no AppError creation.
 * - DB access is limited to snapshot-loading helpers only.
 * - Service orchestration stays in cp-accounts.service.ts.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { SaveCpAccessInput } from './cp-accounts.schemas';
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
  listCpIntegrationConfigSql,
  listCpPersonalFamilyConfigSql,
  listCpPersonalFieldConfigSql,
} from './dal/cp-accounts.query-sql';
import { CpAccountErrors } from './cp-accounts.errors';
import {
  CP_SETUP_GROUPS,
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
import { buildCpSettingsHandoffSnapshot } from './handoff/cp-settings-handoff.builder';

export type AccountSnapshot = {
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

export type ProvisionableTenantConfig = {
  isActive: boolean;
  publicSignupEnabled: boolean;
  adminInviteRequired: boolean;
  memberMfaRequired: boolean;
  allowedEmailDomains: string[];
  allowedSso: Array<'google' | 'microsoft'>;
};

export function normalizeDomains(values: string[]): string[] {
  return Array.from(
    new Set(values.map((value) => value.trim().toLowerCase()).filter((value) => value.length > 0)),
  );
}

export function stableStringify(value: unknown): string {
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

export function accessAllowanceChanged(
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

export function buildStep2Progress(
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

export function buildAccessConfig(
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
      allowedDomains: normalizeStoredDomains(row?.allowed_domains),
    },
  };
}

export function buildAccountSettingsConfig(
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

export function buildModuleSettingsConfig(
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

export function buildPersonalConfig(
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

export function buildIntegrationsConfig(
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

export function integrationAllowed(
  rows: CpIntegrationConfigRow[],
  integrationKey: string,
): boolean {
  return rows.find((row) => row.integration_key === integrationKey)?.is_allowed ?? false;
}

export function moduleGroupConfigured(row: CpModuleConfigRow | undefined): boolean {
  if (!row) return false;
  if (!row.decisions_saved) return false;
  if (!row.personal_enabled) return true;
  return row.personal_subpage_saved;
}

export async function loadAccountSnapshot(
  db: DbExecutor,
  accountKey: string,
): Promise<AccountSnapshot> {
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

export function snapshotToAccountDetail(snapshot: AccountSnapshot): CpAccountDetail {
  const moduleConfigured = moduleGroupConfigured(snapshot.moduleRow);
  const accountWithProgress: CpAccountRow = {
    ...snapshot.account,
    module_settings_configured: moduleConfigured,
  };

  const provisioning = buildProvisioningResult(snapshot);

  const accountDetail: Omit<CpAccountDetail, 'settingsHandoff'> = {
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

  return {
    ...accountDetail,
    settingsHandoff: buildCpSettingsHandoffSnapshot({
      account: accountDetail,
      provisioning,
    }),
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

export function evaluateCpActivationReadiness(account: CpAccountDetail): CpActivationReadiness {
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

export function snapshotToReview(snapshot: AccountSnapshot): CpAccountReview {
  const account = snapshotToAccountDetail(snapshot);

  return {
    account,
    sections: buildReviewSections(account),
    activationReadiness: evaluateCpActivationReadiness(account),
    provisioning: buildProvisioningResult(snapshot),
  };
}

export function deriveProvisionableTenantConfig(
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
