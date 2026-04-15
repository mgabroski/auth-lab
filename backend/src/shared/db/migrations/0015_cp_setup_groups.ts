/**
 * backend/src/shared/db/migrations/0015_cp_setup_groups.ts
 *
 * WHY:
 * - Adds the minimal CP Phase 3 persistence layer for Step 2 setup groups.
 * - Keeps CP provisioning truth separate from tenant Settings truth.
 * - Persists both allowance truth (group config tables) and Step 2 progress truth
 *   (group-configured flags on cp_accounts).
 *
 * TABLES CREATED:
 * - cp_access_config
 * - cp_account_settings_config
 * - cp_module_config
 * - cp_personal_family_config
 * - cp_personal_field_config
 * - cp_integration_config
 *
 * DESIGN RULES:
 * - cp_accounts remains the account identity / revision anchor.
 * - Step 2 progress is persisted via boolean flags on cp_accounts so the CP app
 *   can render real configured/not-configured state without fake frontend truth.
 * - Group tables persist allowance truth only. They are not tenant runtime
 *   settings tables and must not be collapsed with future Settings tables.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    ALTER TABLE cp_accounts
      ADD COLUMN IF NOT EXISTS access_configured           BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS account_settings_configured BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS module_settings_configured  BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS integrations_configured     BOOLEAN NOT NULL DEFAULT FALSE;
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS cp_access_config (
      account_id                  UUID        NOT NULL,
      login_password_allowed      BOOLEAN     NOT NULL DEFAULT TRUE,
      login_google_allowed        BOOLEAN     NOT NULL DEFAULT FALSE,
      login_microsoft_allowed     BOOLEAN     NOT NULL DEFAULT FALSE,
      admin_mfa_required          BOOLEAN     NOT NULL DEFAULT TRUE,
      member_mfa_required         BOOLEAN     NOT NULL DEFAULT FALSE,
      public_signup_allowed       BOOLEAN     NOT NULL DEFAULT FALSE,
      admin_invitations_allowed   BOOLEAN     NOT NULL DEFAULT TRUE,
      allowed_domains             JSONB       NOT NULL DEFAULT '[]'::jsonb,
      created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT cp_access_config_pkey PRIMARY KEY (account_id),
      CONSTRAINT cp_access_config_account_fkey
        FOREIGN KEY (account_id)
        REFERENCES cp_accounts(id)
        ON DELETE CASCADE
    );
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS cp_account_settings_config (
      account_id                       UUID        NOT NULL,
      branding_logo_allowed            BOOLEAN     NOT NULL DEFAULT TRUE,
      branding_menu_color_allowed      BOOLEAN     NOT NULL DEFAULT TRUE,
      branding_font_color_allowed      BOOLEAN     NOT NULL DEFAULT TRUE,
      branding_welcome_message_allowed BOOLEAN     NOT NULL DEFAULT TRUE,
      org_employers_allowed            BOOLEAN     NOT NULL DEFAULT TRUE,
      org_locations_allowed            BOOLEAN     NOT NULL DEFAULT TRUE,
      company_calendar_allowed         BOOLEAN     NOT NULL DEFAULT TRUE,
      created_at                       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at                       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT cp_account_settings_config_pkey PRIMARY KEY (account_id),
      CONSTRAINT cp_account_settings_config_account_fkey
        FOREIGN KEY (account_id)
        REFERENCES cp_accounts(id)
        ON DELETE CASCADE
    );
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS cp_module_config (
      account_id             UUID        NOT NULL,
      personal_enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
      documents_enabled      BOOLEAN     NOT NULL DEFAULT FALSE,
      benefits_enabled       BOOLEAN     NOT NULL DEFAULT FALSE,
      payments_enabled       BOOLEAN     NOT NULL DEFAULT FALSE,
      decisions_saved        BOOLEAN     NOT NULL DEFAULT FALSE,
      personal_subpage_saved BOOLEAN     NOT NULL DEFAULT FALSE,
      created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT cp_module_config_pkey PRIMARY KEY (account_id),
      CONSTRAINT cp_module_config_account_fkey
        FOREIGN KEY (account_id)
        REFERENCES cp_accounts(id)
        ON DELETE CASCADE
    );
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS cp_personal_family_config (
      id          UUID        NOT NULL DEFAULT gen_random_uuid(),
      account_id  UUID        NOT NULL,
      family_key  TEXT        NOT NULL,
      is_allowed  BOOLEAN     NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT cp_personal_family_config_pkey PRIMARY KEY (id),
      CONSTRAINT cp_personal_family_unique UNIQUE (account_id, family_key),
      CONSTRAINT cp_personal_family_account_fkey
        FOREIGN KEY (account_id)
        REFERENCES cp_accounts(id)
        ON DELETE CASCADE
    );
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS cp_personal_field_config (
      id                UUID        NOT NULL DEFAULT gen_random_uuid(),
      account_id        UUID        NOT NULL,
      family_key        TEXT        NOT NULL,
      field_key         TEXT        NOT NULL,
      is_allowed        BOOLEAN     NOT NULL,
      default_selected  BOOLEAN     NOT NULL,
      created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT cp_personal_field_config_pkey PRIMARY KEY (id),
      CONSTRAINT cp_personal_field_unique UNIQUE (account_id, field_key),
      CONSTRAINT cp_personal_field_account_fkey
        FOREIGN KEY (account_id)
        REFERENCES cp_accounts(id)
        ON DELETE CASCADE
    );
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS cp_integration_config (
      id                         UUID        NOT NULL DEFAULT gen_random_uuid(),
      account_id                 UUID        NOT NULL,
      integration_key            TEXT        NOT NULL,
      is_allowed                 BOOLEAN     NOT NULL,
      data_sync_allowed          BOOLEAN,
      import_enabled_allowed     BOOLEAN,
      import_rules_allowed       BOOLEAN,
      field_mapping_allowed      BOOLEAN,
      payments_surface_allowed   BOOLEAN,
      created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT cp_integration_config_pkey PRIMARY KEY (id),
      CONSTRAINT cp_integration_unique UNIQUE (account_id, integration_key),
      CONSTRAINT cp_integration_account_fkey
        FOREIGN KEY (account_id)
        REFERENCES cp_accounts(id)
        ON DELETE CASCADE
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS cp_personal_family_account_idx
      ON cp_personal_family_config (account_id);
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS cp_personal_field_account_idx
      ON cp_personal_field_config (account_id);
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS cp_integration_account_idx
      ON cp_integration_config (account_id);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    DROP INDEX IF EXISTS cp_integration_account_idx;
    DROP INDEX IF EXISTS cp_personal_field_account_idx;
    DROP INDEX IF EXISTS cp_personal_family_account_idx;

    DROP TABLE IF EXISTS cp_integration_config;
    DROP TABLE IF EXISTS cp_personal_field_config;
    DROP TABLE IF EXISTS cp_personal_family_config;
    DROP TABLE IF EXISTS cp_module_config;
    DROP TABLE IF EXISTS cp_account_settings_config;
    DROP TABLE IF EXISTS cp_access_config;

    ALTER TABLE cp_accounts
      DROP COLUMN IF EXISTS integrations_configured,
      DROP COLUMN IF EXISTS module_settings_configured,
      DROP COLUMN IF EXISTS account_settings_configured,
      DROP COLUMN IF EXISTS access_configured;
  `.execute(db);
}
