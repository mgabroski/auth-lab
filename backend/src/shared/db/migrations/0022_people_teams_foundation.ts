/**
 * backend/src/shared/db/migrations/0022_people_teams_foundation.ts
 *
 * WHY:
 * - Introduces the tenant-scoped People & Teams persistence foundation.
 * - Groups are reusable tenant-level teams/audiences that later Operational
 *   Access can consume, but this migration does not implement grants, scopes,
 *   Person Exceptions, or an Effective Access Resolver.
 *
 * RULES:
 * - Current runtime membership roles remain ADMIN / MEMBER.
 * - Group level is classification only: ADMIN / AGENT / USER.
 * - Group membership anchors to tenant memberships, not global users alone.
 * - Archive-only lifecycle in MVP; no hard-delete workflow is introduced here.
 */

import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`.execute(db);

  await sql`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'memberships_id_tenant_unique'
      ) THEN
        ALTER TABLE memberships
          ADD CONSTRAINT memberships_id_tenant_unique UNIQUE (id, tenant_id);
      END IF;
    END $$;
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS tenant_groups (
      id                         UUID        NOT NULL DEFAULT gen_random_uuid(),
      tenant_id                  UUID        NOT NULL,
      name                       TEXT        NOT NULL,
      normalized_name            TEXT        NOT NULL,
      description                TEXT,
      level                      TEXT        NOT NULL,
      status                     TEXT        NOT NULL DEFAULT 'ACTIVE',
      created_by_membership_id   UUID,
      updated_by_membership_id   UUID,
      archived_by_membership_id  UUID,
      archived_at                TIMESTAMPTZ,
      created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_groups_pkey PRIMARY KEY (id),
      CONSTRAINT tenant_groups_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_groups_created_by_membership_fkey
        FOREIGN KEY (created_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_groups_updated_by_membership_fkey
        FOREIGN KEY (updated_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_groups_archived_by_membership_fkey
        FOREIGN KEY (archived_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_groups_id_tenant_unique UNIQUE (id, tenant_id),
      CONSTRAINT tenant_groups_tenant_normalized_name_unique UNIQUE (tenant_id, normalized_name),
      CONSTRAINT tenant_groups_name_not_blank_check CHECK (length(btrim(name)) > 0),
      CONSTRAINT tenant_groups_normalized_name_not_blank_check
        CHECK (length(btrim(normalized_name)) > 0),
      CONSTRAINT tenant_groups_normalized_name_lowercase_check
        CHECK (normalized_name = lower(normalized_name)),
      CONSTRAINT tenant_groups_level_check CHECK (level IN ('ADMIN', 'AGENT', 'USER')),
      CONSTRAINT tenant_groups_status_check CHECK (status IN ('ACTIVE', 'ARCHIVED')),
      CONSTRAINT tenant_groups_archive_metadata_check CHECK (
        (status = 'ACTIVE' AND archived_at IS NULL AND archived_by_membership_id IS NULL)
        OR
        (status = 'ARCHIVED' AND archived_at IS NOT NULL)
      )
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_groups_tenant_status_name_idx
      ON tenant_groups (tenant_id, status, normalized_name);
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS tenant_group_members (
      tenant_id                 UUID        NOT NULL,
      group_id                  UUID        NOT NULL,
      membership_id             UUID        NOT NULL,
      added_by_membership_id    UUID,
      created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_group_members_pkey PRIMARY KEY (group_id, membership_id),
      CONSTRAINT tenant_group_members_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_group_members_group_tenant_fkey
        FOREIGN KEY (group_id, tenant_id)
        REFERENCES tenant_groups(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_group_members_membership_tenant_fkey
        FOREIGN KEY (membership_id, tenant_id)
        REFERENCES memberships(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_group_members_added_by_membership_fkey
        FOREIGN KEY (added_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_group_members_tenant_membership_idx
      ON tenant_group_members (tenant_id, membership_id);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    DROP INDEX IF EXISTS tenant_group_members_tenant_membership_idx;
    DROP TABLE IF EXISTS tenant_group_members;

    DROP INDEX IF EXISTS tenant_groups_tenant_status_name_idx;
    DROP TABLE IF EXISTS tenant_groups;

    ALTER TABLE memberships
      DROP CONSTRAINT IF EXISTS memberships_id_tenant_unique;
  `.execute(db);
}
