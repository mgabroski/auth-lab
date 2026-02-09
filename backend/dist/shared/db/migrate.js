/**
 * backend/src/shared/db/migrate-dist.ts
 *
 * WHY:
 * - Kysely's FileMigrationProvider loads migrations reliably from JS files.
 * - Our migrations are written in TypeScript under src/, but we run them from dist/
 *   after compiling with `tsc`.
 *
 * HOW TO USE:
 * - Do not run directly.
 * - Use: yarn db:migrate
 *   which does:
 *     1) yarn build
 *     2) node dist/shared/db/migrate-dist.js
 */
import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Migrator, FileMigrationProvider } from "kysely";
import { createDb } from "./db.js";
import { buildConfig } from "../../app/config.js";
import { logger } from "../logger/logger.js";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
async function runMigrations() {
    const config = buildConfig();
    const db = createDb(config.databaseUrl);
    // IMPORTANT:
    // This file lives in dist/shared/db/ at runtime,
    // and migrations live in dist/shared/db/migrations
    const migrationsDir = path.join(__dirname, "migrations");
    const migrator = new Migrator({
        db,
        provider: new FileMigrationProvider({
            fs: await import("node:fs/promises"),
            path,
            migrationFolder: migrationsDir,
        }),
    });
    const { error, results } = await migrator.migrateToLatest();
    results?.forEach((it) => {
        if (it.status === "Success") {
            logger.info("migration success", { migration: it.migrationName });
        }
        else if (it.status === "Error") {
            logger.error("migration error", { migration: it.migrationName });
        }
    });
    if (error) {
        logger.error("Migration failed", { error });
        process.exit(1);
    }
    await db.destroy();
    logger.info("Migrations up to date");
}
runMigrations();
