/**
 * backend/src/shared/db/migrations/0028_operational_access_advanced_coverage_versions.ts
 *
 * WHY:
 * - Adds one tenant-scoped optimistic-concurrency guard for advanced
 *   Operational Access saves.
 * - Oversight, Temporary Coverage, and Special Access are security-sensitive;
 *   stale admin screens must not silently overwrite newer subject-scoped saves.
 *
 * RULES:
 * - No row means version 1 and no configured advanced coverage yet.
 * - Every successful advanced coverage mutation increments the tenant version.
 * - Failed/stale mutations fail closed with 409 and do not change coverage rows.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS tenant_oa_advanced_coverage_versions (
      tenant_id                   UUID        NOT NULL PRIMARY KEY,
      version                     INTEGER     NOT NULL DEFAULT 1,
      updated_by_membership_id    UUID,
      updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tenant_oa_advanced_coverage_versions_tenant_fkey
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,
      CONSTRAINT tenant_oa_advanced_coverage_versions_updated_by_fkey
        FOREIGN KEY (updated_by_membership_id)
        REFERENCES memberships(id)
        ON DELETE SET NULL,
      CONSTRAINT tenant_oa_advanced_coverage_versions_version_check
        CHECK (version > 0)
    );
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`DROP TABLE IF EXISTS tenant_oa_advanced_coverage_versions;`.execute(db);
}
