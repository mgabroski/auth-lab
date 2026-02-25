/**
 * backend/src/shared/db/migrations/0009_invites_tenant_listing_idx.ts
 *
 * WHY:
 * - Brick 12 adds admin invite listing (GET /admin/invites) and bulk-cancel on resend.
 * - Without indexes, both operations do full table scans on `invites`.
 *
 * RULES:
 * - No schema changes — only index additions.
 * - All columns already exist from earlier migrations.
 * - Both indexes use IF NOT EXISTS for safe re-runs.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  // Fast paginated listing: WHERE tenant_id = ? ORDER BY created_at DESC
  await sql`
    CREATE INDEX IF NOT EXISTS invites_tenant_id_created_at_desc_idx
    ON invites(tenant_id, created_at DESC);
  `.execute(db);

  // Fast pending lookup by email and bulk-cancel on resend
  await sql`
    CREATE INDEX IF NOT EXISTS invites_tenant_id_email_status_idx
    ON invites(tenant_id, email, status);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`DROP INDEX IF EXISTS invites_tenant_id_email_status_idx;`.execute(db);
  await sql`DROP INDEX IF EXISTS invites_tenant_id_created_at_desc_idx;`.execute(db);
}
