/**
 * backend/src/shared/db/migrations/0010_audit_events_viewer_idx.ts
 *
 * WHY:
 * - GET /admin/audit-events filters by (tenant_id, action) and (tenant_id, user_id)
 *   with ORDER BY created_at DESC. Without indexes both paths do full table scans.
 * - Two composite indexes cover the two most common filter combinations.
 *
 * RULES:
 * - No schema changes — only index additions.
 * - All columns already exist from migration 0003 (audit_events table).
 * - Both indexes use IF NOT EXISTS for safe re-runs.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  // Covers: WHERE tenant_id = ? AND action = ? ORDER BY created_at DESC
  await sql`
    CREATE INDEX IF NOT EXISTS audit_events_tenant_action_created_idx
    ON audit_events(tenant_id, action, created_at DESC);
  `.execute(db);

  // Covers: WHERE tenant_id = ? AND user_id = ? ORDER BY created_at DESC
  await sql`
    CREATE INDEX IF NOT EXISTS audit_events_tenant_user_created_idx
    ON audit_events(tenant_id, user_id, created_at DESC);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`DROP INDEX IF EXISTS audit_events_tenant_user_created_idx;`.execute(db);
  await sql`DROP INDEX IF EXISTS audit_events_tenant_action_created_idx;`.execute(db);
}
