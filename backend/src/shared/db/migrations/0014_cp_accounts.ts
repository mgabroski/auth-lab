/**
 * backend/src/shared/db/migrations/0014_cp_accounts.ts
 *
 * WHY:
 * - Creates the cp_accounts table as the persistence foundation for
 *   the Control Plane accounts subdomain (CP Phase 2).
 *
 * DESIGN:
 * - cp_accounts is the CP-side identity and provisioning truth table.
 *   It is distinct from the tenant-side tenants table.
 *   CP provisioning truth and tenant configuration truth must not be collapsed.
 * - cp_status uses TEXT (not ENUM) to allow future vocabulary extensions
 *   without a schema migration.  Application code validates the vocabulary.
 * - cp_revision starts at 0 and is incremented by application code on
 *   meaningful allowance-truth mutations (group saves that change CP-owned configuration). Publish and status-toggle do not increment it. DB never auto-increments it.
 * - account_key has a UNIQUE constraint enforced at both the DB level and
 *   the service layer (explicit pre-insert check for cleaner error messages).
 *
 * STATUS VOCABULARY (locked):
 * - 'Draft'    — account created but not yet published
 * - 'Active'   — published and reachable by tenants
 * - 'Disabled' — published but access is suspended
 *
 * FUTURE CP TABLES (deferred — not created here):
 * - cp_access_config
 * - cp_account_settings_config
 * - cp_module_config
 * - cp_personal_family_config
 * - cp_personal_field_config
 * - cp_integration_config
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS cp_accounts (
      id            UUID        NOT NULL DEFAULT gen_random_uuid(),
      account_name  TEXT        NOT NULL,
      account_key   TEXT        NOT NULL,
      cp_status     TEXT        NOT NULL DEFAULT 'Draft',
      cp_revision   INTEGER     NOT NULL DEFAULT 0,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

      CONSTRAINT cp_accounts_pkey          PRIMARY KEY (id),
      CONSTRAINT cp_accounts_key_unique    UNIQUE      (account_key)
    );
  `.execute(db);

  // Index to support fast lookups by account_key (used by every GET /cp/accounts/:accountKey).
  await sql`
    CREATE INDEX IF NOT EXISTS cp_accounts_account_key_idx
      ON cp_accounts (account_key);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    DROP INDEX  IF EXISTS cp_accounts_account_key_idx;
    DROP TABLE  IF EXISTS cp_accounts;
  `.execute(db);
}
