/**
 * backend/src/shared/db/migrations/0007_tenants_allowed_sso.ts
 *
 * WHY:
 * - Brick 10 (SSO) requires tenant-scoped allow-list of permitted providers.
 * - Tenant decides whether Google/Microsoft buttons are enabled.
 *
 * RULES:
 * - Additive migration only.
 * - Default to empty array (no SSO enabled).
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema
    .alterTable('tenants')
    .addColumn('allowed_sso', sql`text[]`, (col) => col.notNull().defaultTo(sql`'{}'::text[]`))
    .execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.alterTable('tenants').dropColumn('allowed_sso').execute();
}
