/**
 * backend/src/shared/db/migrations/0026_operational_access_group_grants.ts
 *
 * WHY:
 * - Adds the Step 3 Operational Access configuration foundation for active Agent groups.
 * - Stores product-defined group grants and Responsible For exact-person coverage.
 *
 * RULES:
 * - Defaults remain fail-closed: no row means no configured grant/coverage.
 * - No Assigned Areas table is created because stable employer/location pair IDs do not exist yet.
 * - No Oversight, Temporary Coverage, Special Access, Effective Access Resolver,
 *   runtime visibility, search/export/notification, or module integration tables are created here.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS tenant_oa_group_grants (
      id                         UUID        NOT NULL DEFAULT gen_random_uuid(),
      tenant_id                  UUID        NOT NULL,
      group_id                   UUID        NOT NULL,
      action_key                 TEXT        NOT NULL,
      primary_where              TEXT        NOT NULL,
      which_records_key          TEXT        NOT NULL,
      created_by_membership_id   UUID,
      updated_by_membership_id   UUID,
      created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_oa_group_grants_pkey PRIMARY KEY (id),
      CONSTRAINT tenant_oa_group_grants_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_group_grants_group_tenant_fkey
        FOREIGN KEY (group_id, tenant_id)
        REFERENCES tenant_groups(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_group_grants_created_by_membership_fkey
        FOREIGN KEY (created_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_oa_group_grants_updated_by_membership_fkey
        FOREIGN KEY (updated_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_oa_group_grants_tenant_group_action_unique
        UNIQUE (tenant_id, group_id, action_key),
      CONSTRAINT tenant_oa_group_grants_action_key_check CHECK (action_key IN (
        'tasks.view',
        'tasks.manage',
        'documents.review',
        'checklists.manage',
        'personal_cards.view'
      )),
      CONSTRAINT tenant_oa_group_grants_primary_where_check CHECK (primary_where IN (
        'TENANT_WIDE',
        'ASSIGNED_AREAS',
        'RESPONSIBLE_FOR',
        'REVIEW_QUEUE'
      )),
      CONSTRAINT tenant_oa_group_grants_which_records_check CHECK (which_records_key IN (
        'all_tasks',
        'open_tasks',
        'documents_requiring_review',
        'active_checklists',
        'personal_cards_requiring_attention'
      ))
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_oa_group_grants_tenant_group_idx
      ON tenant_oa_group_grants (tenant_id, group_id);
  `.execute(db);

  await sql`
    CREATE TABLE IF NOT EXISTS tenant_oa_responsible_for (
      tenant_id                  UUID        NOT NULL,
      group_id                   UUID        NOT NULL,
      agent_membership_id        UUID        NOT NULL,
      target_membership_id       UUID        NOT NULL,
      created_by_membership_id   UUID,
      created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_oa_responsible_for_pkey
        PRIMARY KEY (group_id, agent_membership_id, target_membership_id),
      CONSTRAINT tenant_oa_responsible_for_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_responsible_for_group_tenant_fkey
        FOREIGN KEY (group_id, tenant_id)
        REFERENCES tenant_groups(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_responsible_for_agent_tenant_fkey
        FOREIGN KEY (agent_membership_id, tenant_id)
        REFERENCES memberships(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_responsible_for_target_tenant_fkey
        FOREIGN KEY (target_membership_id, tenant_id)
        REFERENCES memberships(id, tenant_id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_responsible_for_created_by_membership_fkey
        FOREIGN KEY (created_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_oa_responsible_for_no_self_check
        CHECK (agent_membership_id <> target_membership_id)
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_oa_responsible_for_tenant_agent_idx
      ON tenant_oa_responsible_for (tenant_id, agent_membership_id);
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS tenant_oa_responsible_for_tenant_target_idx
      ON tenant_oa_responsible_for (tenant_id, target_membership_id);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    DROP INDEX IF EXISTS tenant_oa_responsible_for_tenant_target_idx;
    DROP INDEX IF EXISTS tenant_oa_responsible_for_tenant_agent_idx;
    DROP TABLE IF EXISTS tenant_oa_responsible_for;

    DROP INDEX IF EXISTS tenant_oa_group_grants_tenant_group_idx;
    DROP TABLE IF EXISTS tenant_oa_group_grants;
  `.execute(db);
}
