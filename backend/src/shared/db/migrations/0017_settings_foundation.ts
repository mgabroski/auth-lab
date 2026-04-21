/**
 * backend/src/shared/db/migrations/0017_settings_foundation_phase1.ts
 *
 * WHY:
 * - Creates the Step 10 Phase 1 Settings foundation schema.
 * - Introduces persisted aggregate and per-section setup state without
 *   pretending the full Settings state engine already exists.
 * - Backfills the current auth-phase workspace acknowledgement scaffold into
 *   native Settings rows conservatively so rollout can begin without creating a
 *   competing permanent truth source.
 *
 * DESIGN RULES:
 * - These tables are foundational only. They do not imply the Phase 2 state
 *   engine, read surfaces, or CP cascade service already exist.
 * - No tenant is backfilled to overall COMPLETE from legacy acknowledgement
 *   alone. Legacy ack produces aggregate IN_PROGRESS and Access COMPLETE only.
 * - CP remains the producer of allowance truth and cpRevision. This migration
 *   only stores the latest known CP revision alignment point per tenant.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS tenant_setup_state (
      tenant_id                    UUID        NOT NULL,
      overall_status               TEXT        NOT NULL,
      version                      INTEGER     NOT NULL DEFAULT 1,
      applied_cp_revision          INTEGER     NOT NULL DEFAULT 0,
      last_transition_reason_code  TEXT,
      last_transition_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_saved_at                TIMESTAMPTZ,
      last_saved_by_user_id        UUID,
      last_reviewed_at             TIMESTAMPTZ,
      last_reviewed_by_user_id     UUID,
      created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_setup_state_pkey PRIMARY KEY (tenant_id),
      CONSTRAINT tenant_setup_state_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_setup_state_last_saved_by_user_fkey
        FOREIGN KEY (last_saved_by_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_setup_state_last_reviewed_by_user_fkey
        FOREIGN KEY (last_reviewed_by_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_setup_state_status_check
        CHECK (overall_status IN ('NOT_STARTED', 'IN_PROGRESS', 'COMPLETE', 'NEEDS_REVIEW')),
      CONSTRAINT tenant_setup_state_version_check
        CHECK (version > 0),
      CONSTRAINT tenant_setup_state_applied_cp_revision_check
        CHECK (applied_cp_revision >= 0)
    );
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS tenant_setup_section_state (
      tenant_id                    UUID        NOT NULL,
      section_key                  TEXT        NOT NULL,
      status                       TEXT        NOT NULL,
      version                      INTEGER     NOT NULL DEFAULT 1,
      applied_cp_revision          INTEGER     NOT NULL DEFAULT 0,
      last_transition_reason_code  TEXT,
      last_transition_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_saved_at                TIMESTAMPTZ,
      last_saved_by_user_id        UUID,
      last_reviewed_at             TIMESTAMPTZ,
      last_reviewed_by_user_id     UUID,
      created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_setup_section_state_pkey PRIMARY KEY (tenant_id, section_key),
      CONSTRAINT tenant_setup_section_state_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_setup_section_state_last_saved_by_user_fkey
        FOREIGN KEY (last_saved_by_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_setup_section_state_last_reviewed_by_user_fkey
        FOREIGN KEY (last_reviewed_by_user_id)
        REFERENCES users(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_setup_section_state_section_key_check
        CHECK (section_key IN ('access', 'account', 'personal', 'integrations')),
      CONSTRAINT tenant_setup_section_state_status_check
        CHECK (status IN ('NOT_STARTED', 'IN_PROGRESS', 'COMPLETE', 'NEEDS_REVIEW')),
      CONSTRAINT tenant_setup_section_state_version_check
        CHECK (version > 0),
      CONSTRAINT tenant_setup_section_state_applied_cp_revision_check
        CHECK (applied_cp_revision >= 0)
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_setup_state_overall_status_idx
      ON tenant_setup_state (overall_status);
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_setup_state_applied_cp_revision_idx
      ON tenant_setup_state (applied_cp_revision);
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_setup_section_state_tenant_status_idx
      ON tenant_setup_section_state (tenant_id, status);
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_setup_section_state_section_status_idx
      ON tenant_setup_section_state (section_key, status);
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_setup_section_state_applied_cp_revision_idx
      ON tenant_setup_section_state (applied_cp_revision);
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
    INSERT INTO tenant_setup_state (
      tenant_id,
      overall_status,
      version,
      applied_cp_revision,
      last_transition_reason_code,
      last_transition_at,
      last_saved_at,
      last_saved_by_user_id,
      last_reviewed_at,
      last_reviewed_by_user_id
    )
    SELECT
      tenant.id,
      CASE
        WHEN tenant.setup_completed_at IS NOT NULL THEN 'IN_PROGRESS'
        ELSE 'NOT_STARTED'
      END,
      1,
      COALESCE(tenant_cp_revision.cp_revision, 0),
      CASE
        WHEN tenant.setup_completed_at IS NOT NULL THEN 'LEGACY_AUTH_ACK_BRIDGE'
        ELSE 'FOUNDATION_INITIALIZED'
      END,
      COALESCE(tenant.setup_completed_at, NOW()),
      NULL,
      NULL,
      NULL,
      NULL
    FROM tenants AS tenant
    LEFT JOIN tenant_cp_revision
      ON tenant_cp_revision.tenant_id = tenant.id
    ON CONFLICT (tenant_id) DO NOTHING;
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
    INSERT INTO tenant_setup_section_state (
      tenant_id,
      section_key,
      status,
      version,
      applied_cp_revision,
      last_transition_reason_code,
      last_transition_at,
      last_saved_at,
      last_saved_by_user_id,
      last_reviewed_at,
      last_reviewed_by_user_id
    )
    SELECT
      tenant.id,
      section.section_key,
      CASE
        WHEN section.section_key = 'access' AND tenant.setup_completed_at IS NOT NULL THEN 'COMPLETE'
        ELSE 'NOT_STARTED'
      END,
      1,
      COALESCE(tenant_cp_revision.cp_revision, 0),
      CASE
        WHEN section.section_key = 'access' AND tenant.setup_completed_at IS NOT NULL THEN 'LEGACY_AUTH_ACK_BRIDGE'
        ELSE 'FOUNDATION_INITIALIZED'
      END,
      COALESCE(
        CASE
          WHEN section.section_key = 'access' THEN tenant.setup_completed_at
          ELSE NULL
        END,
        NOW()
      ),
      NULL,
      NULL,
      CASE
        WHEN section.section_key = 'access' AND tenant.setup_completed_at IS NOT NULL THEN tenant.setup_completed_at
        ELSE NULL
      END,
      NULL
    FROM tenants AS tenant
    CROSS JOIN (VALUES ('access'), ('account'), ('personal'), ('integrations')) AS section(section_key)
    LEFT JOIN tenant_cp_revision
      ON tenant_cp_revision.tenant_id = tenant.id
    ON CONFLICT (tenant_id, section_key) DO NOTHING;
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    DROP INDEX IF EXISTS tenant_setup_section_state_applied_cp_revision_idx;
    DROP INDEX IF EXISTS tenant_setup_section_state_section_status_idx;
    DROP INDEX IF EXISTS tenant_setup_section_state_tenant_status_idx;
    DROP INDEX IF EXISTS tenant_setup_state_applied_cp_revision_idx;
    DROP INDEX IF EXISTS tenant_setup_state_overall_status_idx;

    DROP TABLE IF EXISTS tenant_setup_section_state;
    DROP TABLE IF EXISTS tenant_setup_state;
  `.execute(db);
}
