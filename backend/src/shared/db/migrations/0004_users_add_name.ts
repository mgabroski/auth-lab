/**
 * src/shared/db/migrations/0004_users_add_name.ts
 *
 * WHY:
 * - Users need a display name (shown in UI, audit trails, admin dashboards).
 * - Single `name` field (not first/last) because:
 *   - Not all cultures use first/last structure.
 *   - SSO providers return a single display name.
 *   - Simpler to manage; add structured fields later if needed.
 * - Nullable because user records may be created before the person
 *   completes registration (e.g., invite acceptance creates user,
 *   name is set during authentication setup).
 *
 * RULES:
 * - Additive migration only (safe).
 * - No data backfill needed (existing rows get NULL).
 */

import type { Kysely } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable('users').addColumn('name', 'text').execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable('users').dropColumn('name').execute();
}
