/**
 * backend/src/shared/db/migrations/0018_settings_account.ts
 *
 * WHY:
 * - Creates the tenant-scoped Account Settings persistence boundary used by
 *   the real v1 Account Settings surface.
 * - Stores per-card versions, per-card cpRevision alignment, and the minimal
 *   tenant-managed values for Branding, Organization Structure, and Company Calendar.
 * - Backfills one row per existing tenant so the live Account read surface can
 *   resolve without inventing transient frontend truth.
 *
 * DESIGN RULES:
 * - One row per tenant only.
 * - Account remains tenant configuration truth, not CP allowance truth.
 * - Card status is local management clarity only; it must not become a second
 *   aggregate setup engine.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS tenant_account_settings (
      tenant_id                           UUID        NOT NULL,
      branding_status                     TEXT        NOT NULL DEFAULT 'NOT_STARTED',
      branding_version                    INTEGER     NOT NULL DEFAULT 1,
      branding_applied_cp_revision        INTEGER     NOT NULL DEFAULT 0,
      branding_last_saved_at              TIMESTAMPTZ,
      branding_last_saved_by_user_id      UUID,
      branding_logo_url                   TEXT,
      branding_menu_color                 TEXT,
      branding_font_color                 TEXT,
      branding_welcome_message            TEXT,
      org_structure_status                TEXT        NOT NULL DEFAULT 'NOT_STARTED',
      org_structure_version               INTEGER     NOT NULL DEFAULT 1,
      org_structure_applied_cp_revision   INTEGER     NOT NULL DEFAULT 0,
      org_structure_last_saved_at         TIMESTAMPTZ,
      org_structure_last_saved_by_user_id UUID,
      org_employers                       JSONB       NOT NULL DEFAULT '[]'::jsonb,
      org_locations                       JSONB       NOT NULL DEFAULT '[]'::jsonb,
      calendar_status                     TEXT        NOT NULL DEFAULT 'NOT_STARTED',
      calendar_version                    INTEGER     NOT NULL DEFAULT 1,
      calendar_applied_cp_revision        INTEGER     NOT NULL DEFAULT 0,
      calendar_last_saved_at              TIMESTAMPTZ,
      calendar_last_saved_by_user_id      UUID,
      calendar_observed_dates             JSONB       NOT NULL DEFAULT '[]'::jsonb,
      created_at                          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at                          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_account_settings_pkey PRIMARY KEY (tenant_id),
      CONSTRAINT tenant_account_settings_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_account_settings_branding_last_saved_by_user_fkey
        FOREIGN KEY (branding_last_saved_by_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_account_settings_org_last_saved_by_user_fkey
        FOREIGN KEY (org_structure_last_saved_by_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_account_settings_calendar_last_saved_by_user_fkey
        FOREIGN KEY (calendar_last_saved_by_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_account_settings_branding_status_check
        CHECK (branding_status IN ('NOT_STARTED', 'IN_PROGRESS', 'COMPLETE', 'NEEDS_REVIEW')),
      CONSTRAINT tenant_account_settings_org_status_check
        CHECK (org_structure_status IN ('NOT_STARTED', 'IN_PROGRESS', 'COMPLETE', 'NEEDS_REVIEW')),
      CONSTRAINT tenant_account_settings_calendar_status_check
        CHECK (calendar_status IN ('NOT_STARTED', 'IN_PROGRESS', 'COMPLETE', 'NEEDS_REVIEW')),
      CONSTRAINT tenant_account_settings_branding_version_check
        CHECK (branding_version > 0),
      CONSTRAINT tenant_account_settings_org_version_check
        CHECK (org_structure_version > 0),
      CONSTRAINT tenant_account_settings_calendar_version_check
        CHECK (calendar_version > 0),
      CONSTRAINT tenant_account_settings_branding_cp_revision_check
        CHECK (branding_applied_cp_revision >= 0),
      CONSTRAINT tenant_account_settings_org_cp_revision_check
        CHECK (org_structure_applied_cp_revision >= 0),
      CONSTRAINT tenant_account_settings_calendar_cp_revision_check
        CHECK (calendar_applied_cp_revision >= 0)
    );
  `.execute(db);

  await sql`
    WITH tenant_cp_revision AS (
      SELECT
        provisioning.tenant_id,
        account.cp_revision AS cp_revision
      FROM cp_account_provisioning AS provisioning
      INNER JOIN cp_accounts AS account
        ON account.id = provisioning.account_id
    )
    INSERT INTO tenant_account_settings (
      tenant_id,
      branding_applied_cp_revision,
      org_structure_applied_cp_revision,
      calendar_applied_cp_revision
    )
    SELECT
      tenant.id,
      COALESCE(tenant_cp_revision.cp_revision, 0),
      COALESCE(tenant_cp_revision.cp_revision, 0),
      COALESCE(tenant_cp_revision.cp_revision, 0)
    FROM tenants AS tenant
    LEFT JOIN tenant_cp_revision
      ON tenant_cp_revision.tenant_id = tenant.id
    ON CONFLICT (tenant_id) DO NOTHING;
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    DROP TABLE IF EXISTS tenant_account_settings;
  `.execute(db);
}
