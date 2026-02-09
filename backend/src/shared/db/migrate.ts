/**
 * backend/src/shared/db/migrate.ts
 *
 * WHY:
 * - Run migrations in DEV reliably.
 * - TS migrations live in: src/shared/db/migrations
 * - We run this file with `tsx`, so dynamic imports of `.ts` migrations work.
 *
 * HOW TO USE:
 * - yarn workspace @auth-lab/backend db:migrate
 * - root `yarn dev` calls this automatically via scripts/dev.sh
 */

import "dotenv/config";

import path from "node:path";
import { pathToFileURL } from "node:url";
import { readdir } from "node:fs/promises";

import { Migrator } from "kysely";
import { createDb } from "./db.js";
import { buildConfig } from "../../app/config.js";
import { logger } from "../logger/logger.js";

async function runMigrations() {
  const config = buildConfig();
  const db = createDb(config.databaseUrl);

  // IMPORTANT:
  // We point directly to the SOURCE migrations folder.
  // This avoids any dist/path confusion.
  const migrationsDir = path.join(process.cwd(), "src/shared/db/migrations");

  // Provider that loads TS migrations reliably in dev via tsx.
  const provider = {
    async getMigrations() {
      const files = (await readdir(migrationsDir))
        .filter((f) => f.endsWith(".ts"))
        .sort();

      logger.info("Found migration files", { count: files.length, files });

      const migrations: Record<string, { up: any; down: any }> = {};

      for (const file of files) {
        const fullPath = path.join(migrationsDir, file);
        const url = pathToFileURL(fullPath).href;

        // tsx will allow importing TS here
        const mod: any = await import(url);

        const name = file.replace(/\.ts$/, "");
        migrations[name] = { up: mod.up, down: mod.down };
      }

      return migrations;
    },
  };

  const migrator = new Migrator({ db, provider });

  const { error, results } = await migrator.migrateToLatest();

  results?.forEach((r) => {
    if (r.status === "Success")
      logger.info("migration success", { migration: r.migrationName });
    if (r.status === "Error")
      logger.error("migration error", { migration: r.migrationName });
  });

  if (error) {
    logger.error("Migration failed", { error });
    process.exit(1);
  }

  await db.destroy();
  logger.info("Migrations up to date");
}

runMigrations();
