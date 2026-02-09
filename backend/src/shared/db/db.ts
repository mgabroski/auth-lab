/**
 * backend/src/shared/db/db.ts
 *
 * WHY:
 * - Central place to create the Kysely DB connection.
 * - We DO NOT manually maintain table types here.
 * - Types are generated from the real Postgres schema using `db:types`.
 *
 * HOW TO USE:
 * - After running migrations, generate types:
 *     yarn workspace @auth-lab/backend db:types
 * - Then Kysely queries become fully typed using the generated Database interface.
 */

import pg from 'pg';
import { Kysely, PostgresDialect } from 'kysely';

import type { DB } from './database.types';

export type Db = Kysely<DB>;

/**
 * DbExecutor is the only DB "capability" DAL/queries should accept.
 * - Works for both main DB and transactions (later we will pass `trx`).
 * - Prevents leaking concrete DB construction into modules.
 */
export type DbExecutor = Kysely<DB>;

export function createDb(databaseUrl: string): Db {
  const pool = new pg.Pool({
    connectionString: databaseUrl,
    // Safe defaults; you can tune later
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  });

  return new Kysely<DB>({
    dialect: new PostgresDialect({ pool }),
  });
}
