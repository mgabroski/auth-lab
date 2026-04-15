/**
 * backend/src/modules/control-plane/accounts/dal/cp-accounts.repo.ts
 *
 * WHY:
 * - DAL writes for Control Plane accounts and Step 2 group tables.
 * - Phase 3 adds upsert/replace methods for all persisted group surfaces.
 *
 * RULES:
 * - No AppError.
 * - No policies.
 * - No transactions started here.
 * - Services own change detection and revision semantics.
 */

import { sql } from 'kysely';
import type { DbExecutor } from '../../../../shared/db/db';

export type InsertCpAccountParams = {
  accountName: string;
  accountKey: string;
};

export type InsertCpAccountResult = {
  id: string;
  accountKey: string;
  createdAt: Date;
};

export type CpAccountProgressPatch = Partial<{
  accessConfigured: boolean;
  accountSettingsConfigured: boolean;
  moduleSettingsConfigured: boolean;
  integrationsConfigured: boolean;
}>;

export class CpAccountsRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): CpAccountsRepo {
    return new CpAccountsRepo(db);
  }

  async insertAccount(params: InsertCpAccountParams): Promise<InsertCpAccountResult> {
    const row = await this.db
      .insertInto('cp_accounts')
      .values({
        account_name: params.accountName,
        account_key: params.accountKey,
        cp_status: 'Draft',
        cp_revision: 0,
      })
      .returning(['id', 'account_key', 'created_at'])
      .executeTakeFirstOrThrow();

    return {
      id: row.id,
      accountKey: row.account_key,
      createdAt: row.created_at,
    };
  }

  async updateAccountProgressAndRevision(params: {
    accountId: string;
    progressPatch: CpAccountProgressPatch;
    incrementRevision: boolean;
  }): Promise<void> {
    const update: Record<string, unknown> = {};

    if (params.progressPatch.accessConfigured !== undefined) {
      update['access_configured'] = params.progressPatch.accessConfigured;
    }
    if (params.progressPatch.accountSettingsConfigured !== undefined) {
      update['account_settings_configured'] = params.progressPatch.accountSettingsConfigured;
    }
    if (params.progressPatch.moduleSettingsConfigured !== undefined) {
      update['module_settings_configured'] = params.progressPatch.moduleSettingsConfigured;
    }
    if (params.progressPatch.integrationsConfigured !== undefined) {
      update['integrations_configured'] = params.progressPatch.integrationsConfigured;
    }

    update['updated_at'] = new Date();

    if (params.incrementRevision) {
      update['cp_revision'] = sql`cp_revision + 1`;
    }

    await this.db
      .updateTable('cp_accounts')
      .set(update)
      .where('id', '=', params.accountId)
      .executeTakeFirst();
  }

  async upsertAccessConfig(params: {
    accountId: string;
    loginPasswordAllowed: boolean;
    loginGoogleAllowed: boolean;
    loginMicrosoftAllowed: boolean;
    adminMfaRequired: boolean;
    memberMfaRequired: boolean;
    publicSignupAllowed: boolean;
    adminInvitationsAllowed: boolean;
    allowedDomains: string[];
  }): Promise<void> {
    await this.db
      .insertInto('cp_access_config')
      .values({
        account_id: params.accountId,
        login_password_allowed: params.loginPasswordAllowed,
        login_google_allowed: params.loginGoogleAllowed,
        login_microsoft_allowed: params.loginMicrosoftAllowed,
        admin_mfa_required: params.adminMfaRequired,
        member_mfa_required: params.memberMfaRequired,
        public_signup_allowed: params.publicSignupAllowed,
        admin_invitations_allowed: params.adminInvitationsAllowed,
        allowed_domains: params.allowedDomains,
      })
      .onConflict((oc) =>
        oc.column('account_id').doUpdateSet({
          login_password_allowed: params.loginPasswordAllowed,
          login_google_allowed: params.loginGoogleAllowed,
          login_microsoft_allowed: params.loginMicrosoftAllowed,
          admin_mfa_required: params.adminMfaRequired,
          member_mfa_required: params.memberMfaRequired,
          public_signup_allowed: params.publicSignupAllowed,
          admin_invitations_allowed: params.adminInvitationsAllowed,
          allowed_domains: params.allowedDomains,
          updated_at: new Date(),
        }),
      )
      .execute();
  }

  async upsertAccountSettingsConfig(params: {
    accountId: string;
    brandingLogoAllowed: boolean;
    brandingMenuColorAllowed: boolean;
    brandingFontColorAllowed: boolean;
    brandingWelcomeMessageAllowed: boolean;
    orgEmployersAllowed: boolean;
    orgLocationsAllowed: boolean;
    companyCalendarAllowed: boolean;
  }): Promise<void> {
    await this.db
      .insertInto('cp_account_settings_config')
      .values({
        account_id: params.accountId,
        branding_logo_allowed: params.brandingLogoAllowed,
        branding_menu_color_allowed: params.brandingMenuColorAllowed,
        branding_font_color_allowed: params.brandingFontColorAllowed,
        branding_welcome_message_allowed: params.brandingWelcomeMessageAllowed,
        org_employers_allowed: params.orgEmployersAllowed,
        org_locations_allowed: params.orgLocationsAllowed,
        company_calendar_allowed: params.companyCalendarAllowed,
      })
      .onConflict((oc) =>
        oc.column('account_id').doUpdateSet({
          branding_logo_allowed: params.brandingLogoAllowed,
          branding_menu_color_allowed: params.brandingMenuColorAllowed,
          branding_font_color_allowed: params.brandingFontColorAllowed,
          branding_welcome_message_allowed: params.brandingWelcomeMessageAllowed,
          org_employers_allowed: params.orgEmployersAllowed,
          org_locations_allowed: params.orgLocationsAllowed,
          company_calendar_allowed: params.companyCalendarAllowed,
          updated_at: new Date(),
        }),
      )
      .execute();
  }

  async upsertModuleConfig(params: {
    accountId: string;
    personalEnabled: boolean;
    documentsEnabled: boolean;
    benefitsEnabled: boolean;
    paymentsEnabled: boolean;
    decisionsSaved: boolean;
    personalSubpageSaved: boolean;
  }): Promise<void> {
    await this.db
      .insertInto('cp_module_config')
      .values({
        account_id: params.accountId,
        personal_enabled: params.personalEnabled,
        documents_enabled: params.documentsEnabled,
        benefits_enabled: params.benefitsEnabled,
        payments_enabled: params.paymentsEnabled,
        decisions_saved: params.decisionsSaved,
        personal_subpage_saved: params.personalSubpageSaved,
      })
      .onConflict((oc) =>
        oc.column('account_id').doUpdateSet({
          personal_enabled: params.personalEnabled,
          documents_enabled: params.documentsEnabled,
          benefits_enabled: params.benefitsEnabled,
          payments_enabled: params.paymentsEnabled,
          decisions_saved: params.decisionsSaved,
          personal_subpage_saved: params.personalSubpageSaved,
          updated_at: new Date(),
        }),
      )
      .execute();
  }

  async replacePersonalConfig(params: {
    accountId: string;
    families: Array<{ familyKey: string; isAllowed: boolean }>;
    fields: Array<{
      familyKey: string;
      fieldKey: string;
      isAllowed: boolean;
      defaultSelected: boolean;
    }>;
  }): Promise<void> {
    await this.db
      .deleteFrom('cp_personal_family_config')
      .where('account_id', '=', params.accountId)
      .execute();
    await this.db
      .deleteFrom('cp_personal_field_config')
      .where('account_id', '=', params.accountId)
      .execute();

    if (params.families.length > 0) {
      await this.db
        .insertInto('cp_personal_family_config')
        .values(
          params.families.map((family) => ({
            account_id: params.accountId,
            family_key: family.familyKey,
            is_allowed: family.isAllowed,
          })),
        )
        .execute();
    }

    if (params.fields.length > 0) {
      await this.db
        .insertInto('cp_personal_field_config')
        .values(
          params.fields.map((field) => ({
            account_id: params.accountId,
            family_key: field.familyKey,
            field_key: field.fieldKey,
            is_allowed: field.isAllowed,
            default_selected: field.defaultSelected,
          })),
        )
        .execute();
    }
  }

  async replaceIntegrationConfig(params: {
    accountId: string;
    rows: Array<{
      integrationKey: string;
      isAllowed: boolean;
      dataSyncAllowed: boolean | null;
      importEnabledAllowed: boolean | null;
      importRulesAllowed: boolean | null;
      fieldMappingAllowed: boolean | null;
      paymentsSurfaceAllowed: boolean | null;
    }>;
  }): Promise<void> {
    await this.db
      .deleteFrom('cp_integration_config')
      .where('account_id', '=', params.accountId)
      .execute();

    if (params.rows.length === 0) return;

    await this.db
      .insertInto('cp_integration_config')
      .values(
        params.rows.map((row) => ({
          account_id: params.accountId,
          integration_key: row.integrationKey,
          is_allowed: row.isAllowed,
          data_sync_allowed: row.dataSyncAllowed,
          import_enabled_allowed: row.importEnabledAllowed,
          import_rules_allowed: row.importRulesAllowed,
          field_mapping_allowed: row.fieldMappingAllowed,
          payments_surface_allowed: row.paymentsSurfaceAllowed,
        })),
      )
      .execute();
  }
}
