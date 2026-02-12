/**
 * src/shared/db/migrations/0003_invites_audit_indexes.ts
 *
 * WHY:
 * - Brick 6 (Invite acceptance) reads invites by (tenant_id, token_hash).
 *   Composite index guarantees fast lookups and stable query plans.
 * - Audit UI will list events by tenant ordered by time.
 *   Composite index prevents slow sorts and supports pagination.
 *
 * RULES:
 * - Additive migration only (safe).
 * - No business logic here.
 */

import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  // Fast invite lookup: WHERE tenant_id = ? AND token_hash = ?
  await sql`
    CREATE INDEX IF NOT EXISTS invites_tenant_id_token_hash_idx
    ON invites(tenant_id, token_hash);
  `.execute(db);

  // Fast audit listing per tenant: WHERE tenant_id = ? ORDER BY created_at DESC
  await sql`
    CREATE INDEX IF NOT EXISTS audit_events_tenant_id_created_at_desc_idx
    ON audit_events(tenant_id, created_at DESC);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`DROP INDEX IF EXISTS audit_events_tenant_id_created_at_desc_idx;`.execute(db);
  await sql`DROP INDEX IF EXISTS invites_tenant_id_token_hash_idx;`.execute(db);
}
