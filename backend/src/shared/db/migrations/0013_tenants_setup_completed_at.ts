/**
 * backend/src/shared/db/migrations/0013_tenants_setup_completed_at.ts
 *
 * WHY:
 * - Workspace setup state belongs to the tenant, not to individual users (ADR 0003).
 * - When setup_completed_at IS NULL, the admin dashboard shows a non-blocking
 *   banner prompting any admin to configure the workspace.
 * - When any admin visits /admin/settings, POST /auth/workspace-setup-ack sets
 *   setup_completed_at = now(). The banner disappears for all admins immediately.
 *
 * RULES:
 * - Nullable: existing tenants have NULL after migration — every existing admin
 *   will see the banner once on their next login, which is acceptable.
 * - Non-blocking: the banner is informational only. NULL never prevents any
 *   admin action or user login.
 * - One row per tenant: this is tenant-level state, not per-user or per-membership.
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
