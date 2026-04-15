/**
 * backend/src/shared/db/migrations/0016_cp_review_publish.ts
 *
 * WHY:
 * - Adds the minimal Phase 4 persistence layer for Review & Publish.
 * - Persists the real provisioning result separately from both CP allowance
 *   truth and tenant Settings truth.
 *
 * DESIGN:
 * - cp_account_provisioning is the CP-side record of which tenant row was
 *   created or updated by publish.
 * - tenants remains the runtime auth/provisioning table already consumed by
 *   auth flows. Publish writes to that existing runtime table so QA can use the
 *   provisioned tenant immediately.
 * - cpRevision is NOT changed by this migration. Publish/status writes keep the
 *   existing cpRevision semantics and do not introduce a second revision model.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS cp_account_provisioning (
      account_id              UUID        NOT NULL,
      tenant_id               UUID        NOT NULL,
      last_published_status   TEXT        NOT NULL,
      published_at            TIMESTAMPTZ NOT NULL,
      created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT cp_account_provisioning_pkey PRIMARY KEY (account_id),
      CONSTRAINT cp_account_provisioning_account_fkey
        FOREIGN KEY (account_id)
        REFERENCES cp_accounts(id)
        ON DELETE CASCADE,
      CONSTRAINT cp_account_provisioning_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE RESTRICT,
      CONSTRAINT cp_account_provisioning_tenant_unique UNIQUE (tenant_id)
    );
  `.execute(db);

  await sql`
    CREATE INDEX IF NOT EXISTS cp_account_provisioning_tenant_idx
      ON cp_account_provisioning (tenant_id);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    DROP INDEX IF EXISTS cp_account_provisioning_tenant_idx;
    DROP TABLE IF EXISTS cp_account_provisioning;
  `.execute(db);
}
