/**
 * backend/src/shared/db/migrate.ts
 *
 * WHY:
 * - Run migrations in both DEV (tsx + TS source migrations) and container runtime
 *   (plain node + compiled JS migrations).
 */

import 'dotenv/config';

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readdir } from 'node:fs/promises';

import { Migrator, type Migration, type MigrationProvider } from 'kysely';
import { createDb } from './db';
import { buildConfig } from '../../app/config';
import { logger } from '../logger/logger';

async function runMigrations(): Promise<void> {
  const config = buildConfig();
  const db = createDb(config.databaseUrl);

  const thisFilePath = fileURLToPath(import.meta.url);
  const runningCompiledJs = thisFilePath.includes(`${path.sep}dist${path.sep}`);

  const migrationsDir = runningCompiledJs
    ? path.join(process.cwd(), 'dist/shared/db/migrations')
    : path.join(process.cwd(), 'src/shared/db/migrations');

  const expectedExtension = runningCompiledJs ? '.js' : '.ts';

  const provider: MigrationProvider = {
    async getMigrations(): Promise<Record<string, Migration>> {
      const files = (await readdir(migrationsDir))
        .filter((file) => file.endsWith(expectedExtension))
        .sort();

      logger.info('Found migration files', {
        count: files.length,
        files,
        migrationsDir,
        expectedExtension,
      });

      const migrations: Record<string, Migration> = {};

      for (const file of files) {
        const fullPath = path.join(migrationsDir, file);
        const url = pathToFileURL(fullPath).href;
        const mod = (await import(url)) as Migration;

        const name = file.slice(0, -expectedExtension.length);
        migrations[name] = mod;
      }

      return migrations;
    },
  };

  const migrator = new Migrator({ db, provider });

  const { error, results } = await migrator.migrateToLatest();

  results?.forEach((result) => {
    if (result.status === 'Success') {
      logger.info('migration success', { migration: result.migrationName });
    }

    if (result.status === 'Error') {
      logger.error('migration error', { migration: result.migrationName });
    }
  });

  if (error) {
    logger.error('Migration failed', { error });
    process.exit(1);
  }

  await db.destroy();
  logger.info('Migrations up to date');
}

void runMigrations().catch((err: unknown) => {
  logger.error('Migration runner crashed', { err });
  process.exit(1);
});
