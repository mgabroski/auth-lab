import { sql } from 'kysely';
import type { DbExecutor } from '../../src/shared/db/db';

/**
 * Deterministic DB reset for tests.
 *
 * WHY:
 * - Many E2E/DAL tests rely on "unique values" and partial cleanup.
 * - That makes test runs order-dependent and flaky (rerun locally fails).
 *
 * STRATEGY:
 * - TRUNCATE all tables in the public schema except Kysely migration tables.
 * - RESTART IDENTITY keeps sequences consistent for snapshot-like assertions.
 * - CASCADE guarantees FK order is not a maintenance burden.
 */
export async function resetDb(db: DbExecutor): Promise<void> {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('resetDb is test-only and requires NODE_ENV=test');
  }

  await db.transaction().execute(async (trx) => {
    await sql`
      DO $$
      DECLARE
        stmt text;
      BEGIN
        SELECT
          'TRUNCATE TABLE '
          || string_agg(format('%I.%I', schemaname, tablename), ', ')
          || ' RESTART IDENTITY CASCADE'
        INTO stmt
        FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename NOT IN ('kysely_migration', 'kysely_migration_lock');

        IF stmt IS NOT NULL THEN
          EXECUTE stmt;
        END IF;
      END $$;
    `.execute(trx);
  });
}
