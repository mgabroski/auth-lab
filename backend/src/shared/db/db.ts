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

import pg from "pg";
import { Kysely, PostgresDialect } from "kysely";

import type { DB } from "./database.types";

export function createDb(databaseUrl: string) {
  const pool = new pg.Pool({ connectionString: databaseUrl });

  return new Kysely<DB>({
    dialect: new PostgresDialect({ pool }),
  });
}
