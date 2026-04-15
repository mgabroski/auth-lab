/**
 * backend/src/modules/control-plane/accounts/cp-accounts.service.ts
 *
 * WHY:
 * - Business orchestration for CP accounts and real Phase 3 Step 2 group saves.
 * - Owns uniqueness checks, group validation, progress-state updates, and
 *   cpRevision mutation rules.
 *
 * RULES:
 * - All DB writes happen through the repo in a single transaction per request.
 * - cpRevision increments only on meaningful persisted CP allowance mutations.
 * - CP provisioning truth remains separate from tenant Settings truth.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { Logger } from '../../../shared/logger/logger';
import type {
  CreateCpAccountInput,
  SaveCpAccessInput,
  SaveCpAccountSettingsInput,
  SaveCpIntegrationsInput,
  SaveCpModuleSettingsInput,
  SaveCpPersonalInput,
} from './cp-accounts.schemas';
import type { CpAccountsRepo } from './dal/cp-accounts.repo';
import type {
  CpAccessConfigRow,
  CpAccountRow,
  CpAccountSettingsConfigRow,
  CpIntegrationConfigRow,
  CpModuleConfigRow,
  CpPersonalFamilyConfigRow,
  CpPersonalFieldConfigRow,
} from './dal/cp-accounts.query-sql';
import {
  findCpAccessConfigSql,
  findCpAccountByKeySql,
  findCpAccountSettingsConfigSql,
  findCpModuleConfigSql,
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
  CpAccountSettingsConfig,
  CpIntegrationsConfig,
  CpIntegrationConfigItem,
  CpModuleSettingsConfig,
  CpPersonalConfig,
  CpPersonalFamily,
  CpPersonalField,
  CpStatus,
  CpStep2Progress,
} from './cp-accounts.types';

function normalizeDomains(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean)));
}

function stableStringify(value: unknown): string {
  return JSON.stringify(value);
}

function buildStep2Progress(account: CpAccountRow): CpStep2Progress {
  const groups = CP_SETUP_GROUPS.map((group) => ({
    slug: group.slug,
    title: group.title,
    isRequired: group.isRequired,
    configured:
      group.slug === 'access-identity-security'
        ? account.access_configured
        : group.slug === 'account-settings'
          ? account.account_settings_configured
          : group.slug === 'module-settings'
            ? account.module_settings_configured
            : account.integrations_configured,
  }));

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

type AccountSnapshot = {
  account: CpAccountRow;
  accessRow: CpAccessConfigRow | undefined;
  accountSettingsRow: CpAccountSettingsConfigRow | undefined;
  moduleRow: CpModuleConfigRow | undefined;
  personalFamilyRows: CpPersonalFamilyConfigRow[];
  personalFieldRows: CpPersonalFieldConfigRow[];
  integrationRows: CpIntegrationConfigRow[];
};

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
  ] = await Promise.all([
    findCpAccessConfigSql(db, account.id),
    findCpAccountSettingsConfigSql(db, account.id),
    findCpModuleConfigSql(db, account.id),
    listCpPersonalFamilyConfigSql(db, account.id),
    listCpPersonalFieldConfigSql(db, account.id),
    listCpIntegrationConfigSql(db, account.id),
  ]);

  return {
    account,
    accessRow,
    accountSettingsRow,
    moduleRow,
    personalFamilyRows,
    personalFieldRows,
    integrationRows,
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

export class CpAccountsService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      logger: Logger;
      cpAccountsRepo: CpAccountsRepo;
    },
  ) {}

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

      const previous = buildAccessConfig(snapshot.accessRow, snapshot.account.access_configured);
      const next: CpAccessConfig = {
        configured: true,
        loginMethods: normalized.loginMethods,
        mfaPolicy: normalized.mfaPolicy,
        signupPolicy: normalized.signupPolicy,
      };
      const changed = stableStringify(previous) !== stableStringify(next);

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

      const familyAllowedMap = new Map(
        input.families.map((family) => [family.familyKey, family.isAllowed]),
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
          id: 'preview',
          account_id: snapshot.account.id,
          family_key: family.familyKey,
          is_allowed: family.isAllowed,
          created_at: new Date(),
          updated_at: new Date(),
        })),
        normalizedFields.map((field) => ({
          id: 'preview',
          account_id: snapshot.account.id,
          family_key: field.familyKey,
          field_key: field.fieldKey,
          is_allowed: field.isAllowed,
          default_selected: field.defaultSelected,
          created_at: new Date(),
          updated_at: new Date(),
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
          id: 'preview',
          account_id: snapshot.account.id,
          integration_key: row.integrationKey,
          is_allowed: row.isAllowed,
          data_sync_allowed: row.dataSyncAllowed,
          import_enabled_allowed: row.importEnabledAllowed,
          import_rules_allowed: row.importRulesAllowed,
          field_mapping_allowed: row.fieldMappingAllowed,
          payments_surface_allowed: row.paymentsSurfaceAllowed,
          created_at: new Date(),
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
}
