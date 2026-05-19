/**
 * backend/src/shared/db/migrations/0025_operational_access_capability.ts
 *
 * WHY:
 * - Adds the fail-closed tenant capability boundary for future Operational Access.
 * - Keeps the CP-owned decision on cp_accounts and the published tenant runtime
 *   projection on tenants so Settings/admin can hide the safe shell unless the
 *   capability is explicitly enabled.
 *
 * DESIGN:
 * - Defaults to FALSE everywhere. Existing/simple tenants remain safe and do not
 *   see Operational Access surfaces after migration.
 * - This is only a capability boundary. It does not create grants, scopes,
 *   coverage, resolver tables, runtime visibility, or module integrations.
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    ALTER TABLE cp_accounts
      ADD COLUMN IF NOT EXISTS operational_access_enabled BOOLEAN NOT NULL DEFAULT FALSE;
  `.execute(db);

  await sql`
    ALTER TABLE tenants
      ADD COLUMN IF NOT EXISTS operational_access_enabled BOOLEAN NOT NULL DEFAULT FALSE;
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    ALTER TABLE tenants
      DROP COLUMN IF EXISTS operational_access_enabled;

    ALTER TABLE cp_accounts
      DROP COLUMN IF EXISTS operational_access_enabled;
  `.execute(db);
}
