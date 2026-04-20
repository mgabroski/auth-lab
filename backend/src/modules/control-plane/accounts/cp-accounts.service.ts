/**
 * backend/src/modules/control-plane/accounts/cp-accounts.service.ts
 *
 * WHY:
 * - Business orchestration for CP accounts, Step 2 group saves, Review & Publish,
 *   and published-account status changes.
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
import type { AuditRepo } from '../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../shared/audit/audit.writer';
import { AppError } from '../../../shared/http/errors';
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
import {
  findCpAccountByKeySql,
  findTenantProvisioningByKeySql,
  listCpAccountsSql,
} from './dal/cp-accounts.query-sql';
import { CpAccountErrors } from './cp-accounts.errors';
import {
  auditCpAccessSaved,
  auditCpAccessSaveFailed,
  auditCpAccountCreateFailed,
  auditCpAccountCreated,
  auditCpAccountPublishFailed,
  auditCpAccountPublished,
  auditCpAccountSettingsSaved,
  auditCpAccountSettingsSaveFailed,
  auditCpAccountStatusToggled,
  auditCpAccountStatusToggleFailed,
  auditCpIntegrationsSaved,
  auditCpIntegrationsSaveFailed,
  auditCpModuleSettingsSaved,
  auditCpModuleSettingsSaveFailed,
  auditCpPersonalSaved,
  auditCpPersonalSaveFailed,
  type CpAuditRequestContext,
} from './cp-accounts.audit';
import {
  EDITABLE_PERSONAL_FIELD_CATALOG,
  GOOGLE_SSO_INTEGRATION_KEY,
  INTEGRATION_CATALOG,
  MICROSOFT_SSO_INTEGRATION_KEY,
  PERSONAL_FAMILY_DEFAULTS,
  REQUIRED_BASELINE_PERSONAL_FIELD_KEYS,
  type PersonalFamilyKey,
} from './cp-accounts.catalog';
import {
  type AccountSnapshot,
  accessAllowanceChanged,
  buildAccessConfig,
  buildAccountSettingsConfig,
  buildIntegrationsConfig,
  buildModuleSettingsConfig,
  buildPersonalConfig,
  buildStep2Progress,
  deriveProvisionableTenantConfig,
  integrationAllowed,
  loadAccountSnapshot,
  moduleGroupConfigured,
  normalizeDomains,
  snapshotToAccountDetail,
  snapshotToReview,
  stableStringify,
} from './cp-accounts.domain';
import type {
  CpAccountDetail,
  CpAccountListRow,
  CpAccountReview,
  CpAccountSettingsConfig,
  CpModuleSettingsConfig,
  CpStatus,
} from './cp-accounts.types';
import type { CpSettingsHandoffSnapshot } from './handoff/cp-settings-handoff.types';

const RESERVED_ACCOUNT_KEYS = new Set(['cp', 'api', 'admin', 'auth', 'www', 'app']);

export class CpAccountsService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      logger: Logger;
      auditRepo: AuditRepo;
      cpAccountsRepo: CpAccountsRepo;
    },
  ) {}

  private buildAuditWriter(db: DbExecutor, context?: CpAuditRequestContext): AuditWriter {
    return new AuditWriter(this.deps.auditRepo.withDb(db), {
      requestId: context?.requestId ?? null,
      ip: context?.ip ?? null,
      userAgent: context?.userAgent ?? null,
    });
  }

  private buildFailureAuditWriter(context?: CpAuditRequestContext): AuditWriter {
    return new AuditWriter(this.deps.auditRepo, {
      requestId: context?.requestId ?? null,
      ip: context?.ip ?? null,
      userAgent: context?.userAgent ?? null,
    });
  }

  private getFailureAuditMetadata(error: unknown): { errorCode: string; message: string } {
    if (error instanceof AppError) {
      return {
        errorCode: error.code,
        message: error.message,
      };
    }

    if (error instanceof Error) {
      return {
        errorCode: 'INTERNAL',
        message: error.message,
      };
    }

    return {
      errorCode: 'INTERNAL',
      message: 'Unknown Control Plane accounts mutation failure.',
    };
  }

  private async writeFailureAudit(params: {
    accountKey: string;
    context?: CpAuditRequestContext;
    error: unknown;
    action: (
      writer: AuditWriter,
      data: {
        accountId: string | null;
        accountKey: string;
        errorCode: string;
        message: string;
      },
    ) => Promise<void>;
    logEvent: string;
  }): Promise<void> {
    try {
      const account = await findCpAccountByKeySql(this.deps.db, params.accountKey);
      const writer = this.buildFailureAuditWriter(params.context);
      const failure = this.getFailureAuditMetadata(params.error);

      await params.action(writer, {
        accountId: account?.id ?? null,
        accountKey: params.accountKey,
        errorCode: failure.errorCode,
        message: failure.message,
      });
    } catch (auditError) {
      this.deps.logger.error(params.logEvent, {
        event: params.logEvent,
        accountKey: params.accountKey,
        err: auditError,
      });
    }
  }

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

  async createAccount(
    input: CreateCpAccountInput,
    auditContext?: CpAuditRequestContext,
  ): Promise<CpAccountDetail> {
    try {
      if (RESERVED_ACCOUNT_KEYS.has(input.accountKey)) {
        throw CpAccountErrors.reservedAccountKey(input.accountKey);
      }

      return await this.deps.db.transaction().execute(async (trx) => {
        const existing = await findCpAccountByKeySql(trx, input.accountKey);

        if (existing) {
          throw CpAccountErrors.accountKeyConflict(input.accountKey);
        }

        const { id, accountKey } = await this.deps.cpAccountsRepo.withDb(trx).insertAccount({
          accountName: input.accountName,
          accountKey: input.accountKey,
        });

        const snapshot = await loadAccountSnapshot(trx, accountKey);
        const audit = this.buildAuditWriter(trx, auditContext);

        await auditCpAccountCreated(audit, {
          accountId: snapshot.account.id,
          accountKey: snapshot.account.account_key,
          cpRevision: snapshot.account.cp_revision,
        });

        this.deps.logger.info('cp.accounts.created', {
          event: 'cp.accounts.created',
          accountKey,
          id,
        });

        return snapshotToAccountDetail(snapshot);
      });
    } catch (error) {
      await this.writeFailureAudit({
        accountKey: input.accountKey,
        context: auditContext,
        error,
        action: auditCpAccountCreateFailed,
        logEvent: 'cp.accounts.create.failure_audit_failed',
      });
      throw error;
    }
  }

  async getAccount(accountKey: string): Promise<CpAccountDetail> {
    const snapshot = await loadAccountSnapshot(this.deps.db, accountKey);
    return snapshotToAccountDetail(snapshot);
  }

  async getReview(accountKey: string): Promise<CpAccountReview> {
    const snapshot = await loadAccountSnapshot(this.deps.db, accountKey);
    return snapshotToReview(snapshot);
  }

  async getSettingsHandoff(accountKey: string): Promise<CpSettingsHandoffSnapshot> {
    const snapshot = await loadAccountSnapshot(this.deps.db, accountKey);
    return snapshotToAccountDetail(snapshot).settingsHandoff;
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

  async saveAccess(
    accountKey: string,
    input: SaveCpAccessInput,
    auditContext?: CpAuditRequestContext,
  ): Promise<CpAccountDetail> {
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

    try {
      return await this.deps.db.transaction().execute(async (trx) => {
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

        const updatedSnapshot = await loadAccountSnapshot(trx, accountKey);
        const audit = this.buildAuditWriter(trx, auditContext);

        await auditCpAccessSaved(audit, {
          accountId: updatedSnapshot.account.id,
          accountKey: updatedSnapshot.account.account_key,
          cpRevision: updatedSnapshot.account.cp_revision,
          changed,
        });

        return snapshotToAccountDetail(updatedSnapshot);
      });
    } catch (error) {
      await this.writeFailureAudit({
        accountKey,
        context: auditContext,
        error,
        action: auditCpAccessSaveFailed,
        logEvent: 'cp.accounts.access.failure_audit_failed',
      });
      throw error;
    }
  }

  async saveAccountSettings(
    accountKey: string,
    input: SaveCpAccountSettingsInput,
    auditContext?: CpAuditRequestContext,
  ): Promise<CpAccountDetail> {
    try {
      return await this.deps.db.transaction().execute(async (trx) => {
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

        const updatedSnapshot = await loadAccountSnapshot(trx, accountKey);
        const audit = this.buildAuditWriter(trx, auditContext);

        await auditCpAccountSettingsSaved(audit, {
          accountId: updatedSnapshot.account.id,
          accountKey: updatedSnapshot.account.account_key,
          cpRevision: updatedSnapshot.account.cp_revision,
          changed,
        });

        return snapshotToAccountDetail(updatedSnapshot);
      });
    } catch (error) {
      await this.writeFailureAudit({
        accountKey,
        context: auditContext,
        error,
        action: auditCpAccountSettingsSaveFailed,
        logEvent: 'cp.accounts.account_settings.failure_audit_failed',
      });
      throw error;
    }
  }

  async saveModuleSettings(
    accountKey: string,
    input: SaveCpModuleSettingsInput,
    auditContext?: CpAuditRequestContext,
  ): Promise<CpAccountDetail> {
    try {
      return await this.deps.db.transaction().execute(async (trx) => {
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

        const updatedSnapshot = await loadAccountSnapshot(trx, accountKey);
        const audit = this.buildAuditWriter(trx, auditContext);

        await auditCpModuleSettingsSaved(audit, {
          accountId: updatedSnapshot.account.id,
          accountKey: updatedSnapshot.account.account_key,
          cpRevision: updatedSnapshot.account.cp_revision,
          changed,
        });

        return snapshotToAccountDetail(updatedSnapshot);
      });
    } catch (error) {
      await this.writeFailureAudit({
        accountKey,
        context: auditContext,
        error,
        action: auditCpModuleSettingsSaveFailed,
        logEvent: 'cp.accounts.modules.failure_audit_failed',
      });
      throw error;
    }
  }

  async savePersonal(
    accountKey: string,
    input: SaveCpPersonalInput,
    auditContext?: CpAuditRequestContext,
  ): Promise<CpAccountDetail> {
    try {
      return await this.deps.db.transaction().execute(async (trx) => {
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
          const payloadField = input.fields.find(
            (field) => field.fieldKey === catalogField.fieldKey,
          );

          if (!payloadField) {
            throw CpAccountErrors.personalValidation(
              'Personal save is missing one or more field rows.',
            );
          }

          const familyAllowed = familyAllowedMap.get(catalogField.familyKey) ?? true;
          const requiredBaseline = REQUIRED_BASELINE_PERSONAL_FIELD_KEYS.has(catalogField.fieldKey);
          const isAllowed = requiredBaseline
            ? true
            : familyAllowed
              ? payloadField.isAllowed
              : false;
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

        const updatedSnapshot = await loadAccountSnapshot(trx, accountKey);
        const audit = this.buildAuditWriter(trx, auditContext);

        await auditCpPersonalSaved(audit, {
          accountId: updatedSnapshot.account.id,
          accountKey: updatedSnapshot.account.account_key,
          cpRevision: updatedSnapshot.account.cp_revision,
          changed,
        });

        return snapshotToAccountDetail(updatedSnapshot);
      });
    } catch (error) {
      await this.writeFailureAudit({
        accountKey,
        context: auditContext,
        error,
        action: auditCpPersonalSaveFailed,
        logEvent: 'cp.accounts.personal.failure_audit_failed',
      });
      throw error;
    }
  }

  async saveIntegrations(
    accountKey: string,
    input: SaveCpIntegrationsInput,
    auditContext?: CpAuditRequestContext,
  ): Promise<CpAccountDetail> {
    try {
      return await this.deps.db.transaction().execute(async (trx) => {
        const repo = this.deps.cpAccountsRepo.withDb(trx);
        const snapshot = await loadAccountSnapshot(trx, accountKey);
        const access = buildAccessConfig(snapshot.accessRow, snapshot.account.access_configured);

        if (input.integrations.length !== INTEGRATION_CATALOG.length) {
          throw CpAccountErrors.integrationsValidation(
            'Integrations save must include the full integration set for the current CP catalog.',
          );
        }

        const integrationRows = INTEGRATION_CATALOG.map((catalogIntegration) => {
          const payload = input.integrations.find(
            (integration) => integration.integrationKey === catalogIntegration.integrationKey,
          );

          if (!payload) {
            throw CpAccountErrors.integrationsValidation(
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

        const updatedSnapshot = await loadAccountSnapshot(trx, accountKey);
        const audit = this.buildAuditWriter(trx, auditContext);

        await auditCpIntegrationsSaved(audit, {
          accountId: updatedSnapshot.account.id,
          accountKey: updatedSnapshot.account.account_key,
          cpRevision: updatedSnapshot.account.cp_revision,
          changed,
        });

        return snapshotToAccountDetail(updatedSnapshot);
      });
    } catch (error) {
      await this.writeFailureAudit({
        accountKey,
        context: auditContext,
        error,
        action: auditCpIntegrationsSaveFailed,
        logEvent: 'cp.accounts.integrations.failure_audit_failed',
      });
      throw error;
    }
  }

  async updateStatus(
    accountKey: string,
    input: UpdateCpAccountStatusInput,
    auditContext?: CpAuditRequestContext,
  ): Promise<CpAccountDetail> {
    try {
      return await this.deps.db.transaction().execute(async (trx) => {
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

        const updatedSnapshot = await loadAccountSnapshot(trx, accountKey);
        const audit = this.buildAuditWriter(trx, auditContext);

        await auditCpAccountStatusToggled(audit, {
          accountId: updatedSnapshot.account.id,
          accountKey: updatedSnapshot.account.account_key,
          targetStatus: input.targetStatus,
          cpRevision: updatedSnapshot.account.cp_revision,
          tenantId: updatedSnapshot.provisioningRow?.tenant_id ?? null,
        });

        return snapshotToAccountDetail(updatedSnapshot);
      });
    } catch (error) {
      await this.writeFailureAudit({
        accountKey,
        context: auditContext,
        error,
        action: auditCpAccountStatusToggleFailed,
        logEvent: 'cp.accounts.status_toggle.failure_audit_failed',
      });
      throw error;
    }
  }

  async publishAccount(
    accountKey: string,
    input: PublishCpAccountInput,
    auditContext?: CpAuditRequestContext,
  ): Promise<CpAccountReview> {
    try {
      return await this.deps.db.transaction().execute(async (trx) => {
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

        const updatedSnapshot = await loadAccountSnapshot(trx, accountKey);
        const audit = this.buildAuditWriter(trx, auditContext);

        await auditCpAccountPublished(audit, {
          accountId: updatedSnapshot.account.id,
          accountKey: updatedSnapshot.account.account_key,
          targetStatus: input.targetStatus,
          cpRevision: updatedSnapshot.account.cp_revision,
          tenantId: updatedSnapshot.provisioningRow?.tenant_id ?? null,
        });

        return snapshotToReview(updatedSnapshot);
      });
    } catch (error) {
      await this.writeFailureAudit({
        accountKey,
        context: auditContext,
        error,
        action: auditCpAccountPublishFailed,
        logEvent: 'cp.accounts.publish.failure_audit_failed',
      });
      throw error;
    }
  }
}
