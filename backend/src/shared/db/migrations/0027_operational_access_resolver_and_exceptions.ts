/**
 * backend/src/shared/db/migrations/0027_operational_access_resolver_and_exceptions.ts
 *
 * WHY:
 * - Adds the minimal advanced Operational Access persistence needed for the
 *   resolver proof surface: Oversight, Temporary Coverage, and Special Access.
 *
 * RULES:
 * - Defaults remain fail-closed: no row means no extra access.
 * - This migration does not create module-specific tables or broad consumer
 *   integrations.
 * - Assigned Areas remains deferred because stable employer/location target IDs
 *   still do not exist.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS tenant_oa_oversight (
      tenant_id                         UUID        NOT NULL,
      overseer_membership_id            UUID        NOT NULL,
      target_membership_id              UUID        NOT NULL,
      includes_responsible_people       BOOLEAN     NOT NULL DEFAULT FALSE,
      reason                            TEXT        NOT NULL,
      review_at                         TIMESTAMPTZ NOT NULL,
      created_by_membership_id          UUID,
      created_at                        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at                        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_oa_oversight_pkey
        PRIMARY KEY (tenant_id, overseer_membership_id, target_membership_id),
      CONSTRAINT tenant_oa_oversight_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_oversight_overseer_tenant_fkey
        FOREIGN KEY (overseer_membership_id, tenant_id)
        REFERENCES memberships(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_oversight_target_tenant_fkey
        FOREIGN KEY (target_membership_id, tenant_id)
        REFERENCES memberships(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_oversight_created_by_membership_fkey
        FOREIGN KEY (created_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_oa_oversight_no_self_check
        CHECK (overseer_membership_id <> target_membership_id),
      CONSTRAINT tenant_oa_oversight_reason_non_empty_check
        CHECK (length(trim(reason)) > 0)
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_oa_oversight_tenant_overseer_idx
      ON tenant_oa_oversight (tenant_id, overseer_membership_id);
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_oa_oversight_tenant_target_idx
      ON tenant_oa_oversight (tenant_id, target_membership_id);
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS tenant_oa_temporary_coverage (
      id                                UUID        NOT NULL DEFAULT gen_random_uuid(),
      tenant_id                         UUID        NOT NULL,
      covering_membership_id            UUID        NOT NULL,
      covered_membership_id             UUID        NOT NULL,
      starts_at                         TIMESTAMPTZ NOT NULL,
      expires_at                        TIMESTAMPTZ NOT NULL,
      reason                            TEXT        NOT NULL,
      review_at                         TIMESTAMPTZ,
      created_by_membership_id          UUID,
      created_at                        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_oa_temporary_coverage_pkey PRIMARY KEY (id),
      CONSTRAINT tenant_oa_temporary_coverage_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_temporary_coverage_covering_tenant_fkey
        FOREIGN KEY (covering_membership_id, tenant_id)
        REFERENCES memberships(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_temporary_coverage_covered_tenant_fkey
        FOREIGN KEY (covered_membership_id, tenant_id)
        REFERENCES memberships(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_temporary_coverage_created_by_membership_fkey
        FOREIGN KEY (created_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_oa_temporary_coverage_no_self_check
        CHECK (covering_membership_id <> covered_membership_id),
      CONSTRAINT tenant_oa_temporary_coverage_window_check
        CHECK (starts_at < expires_at),
      CONSTRAINT tenant_oa_temporary_coverage_reason_non_empty_check
        CHECK (length(trim(reason)) > 0)
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_oa_temporary_coverage_active_idx
      ON tenant_oa_temporary_coverage (tenant_id, covering_membership_id, starts_at, expires_at);
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS tenant_oa_special_access (
      id                                UUID        NOT NULL DEFAULT gen_random_uuid(),
      tenant_id                         UUID        NOT NULL,
      membership_id                     UUID        NOT NULL,
      target_membership_id              UUID        NOT NULL,
      action_key                        TEXT        NOT NULL,
      reason                            TEXT        NOT NULL,
      review_at                         TIMESTAMPTZ NOT NULL,
      expires_at                        TIMESTAMPTZ NOT NULL,
      created_by_membership_id          UUID,
      revoked_at                        TIMESTAMPTZ,
      created_at                        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_oa_special_access_pkey PRIMARY KEY (id),
      CONSTRAINT tenant_oa_special_access_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_special_access_member_tenant_fkey
        FOREIGN KEY (membership_id, tenant_id)
        REFERENCES memberships(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_special_access_target_tenant_fkey
        FOREIGN KEY (target_membership_id, tenant_id)
        REFERENCES memberships(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_special_access_created_by_membership_fkey
        FOREIGN KEY (created_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_oa_special_access_no_self_check
        CHECK (membership_id <> target_membership_id),
      CONSTRAINT tenant_oa_special_access_reason_non_empty_check
        CHECK (length(trim(reason)) > 0),
      CONSTRAINT tenant_oa_special_access_expiry_check
        CHECK (expires_at > created_at),
      CONSTRAINT tenant_oa_special_access_action_key_check CHECK (action_key IN (
        'tasks.view',
        'tasks.manage',
        'documents.review',
        'checklists.manage',
        'personal_cards.view'
      ))
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_oa_special_access_active_idx
      ON tenant_oa_special_access (tenant_id, membership_id, action_key, expires_at)
      WHERE revoked_at IS NULL;
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    DROP INDEX IF EXISTS tenant_oa_special_access_active_idx;
    DROP TABLE IF EXISTS tenant_oa_special_access;

    DROP INDEX IF EXISTS tenant_oa_temporary_coverage_active_idx;
    DROP TABLE IF EXISTS tenant_oa_temporary_coverage;

    DROP INDEX IF EXISTS tenant_oa_oversight_tenant_target_idx;
    DROP INDEX IF EXISTS tenant_oa_oversight_tenant_overseer_idx;
    DROP TABLE IF EXISTS tenant_oa_oversight;
  `.execute(db);
}
