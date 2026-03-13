/**
 * backend/src/shared/db/migrations/0012_tenants_admin_invite_required.ts
 *
 * WHY:
 * - Phase 1A needs explicit schema parity with the provisioning contract.
 * - "Admin Invite Required" is a first-class tenant policy input and must not
 *   be inferred indirectly from public_signup_enabled.
 *
 * RULES:
 * - Additive migration only.
 * - Default false to preserve all existing tenant behavior.
 * - No enforcement wiring in this migration — later phases will decide policy use.
 */

import type { Kysely } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema
    .alterTable('tenants')
    .addColumn('admin_invite_required', 'boolean', (col) => col.notNull().defaultTo(false))
    .execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable('tenants').dropColumn('admin_invite_required').execute();
}
