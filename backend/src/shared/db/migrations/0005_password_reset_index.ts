/**
 * src/shared/db/migrations/0005_password_reset_index.ts
 *
 * WHY:
 * - Migration files are the single source of truth for DB schema changes.
 *
 * HOW TO USE:
 * - Run all migrations:
 *     yarn db:migrate
 */

import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  // Fast lookup of valid (not-yet-used) reset tokens
  await sql`
    CREATE INDEX IF NOT EXISTS password_reset_tokens_active_idx
    ON password_reset_tokens(token_hash)
    WHERE used_at IS NULL;
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`DROP INDEX IF EXISTS password_reset_tokens_active_idx;`.execute(db);
}
