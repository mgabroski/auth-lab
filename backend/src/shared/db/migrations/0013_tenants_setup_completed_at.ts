/**
 * backend/src/shared/db/migrations/0013_tenants_setup_completed_at.ts
 *
 * WHY:
 * - Workspace setup state belongs to the tenant, not to individual users (ADR 0003).
 * - This column was the auth-phase workspace setup acknowledgement scaffold.
 * - The active Settings UI no longer reads it for banner or completion truth;
 *   `/admin` now uses `GET /settings/bootstrap`.
 * - The column is retained for conservative legacy backfill compatibility and
 *   `/auth/config` response compatibility only.
 *
 * RULES:
 * - Nullable: existing tenants may have NULL.
 * - Non-blocking: NULL never prevents any admin action or user login.
 * - One row per tenant: this is tenant-level historical data, not per-user or
 *   per-membership data.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS setup_completed_at TIMESTAMPTZ NULL;
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    ALTER TABLE tenants
    DROP COLUMN IF EXISTS setup_completed_at;
  `.execute(db);
}
