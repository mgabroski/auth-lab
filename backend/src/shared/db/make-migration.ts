/**
 * backend/src/shared/db/make-migration.ts
 *
 * WHY:
 * - We want a "one command" way to create a new migration file.
 * - Kysely doesn't auto-generate migrations from models/entities.
 * - This script generates:
 *   1) the next migration number (0001, 0002, ...)
 *   2) a standard migration file with `up()` and `down()`
 *
 * HOW TO USE:
 * - Run from repo root (recommended):
 *     yarn workspace @auth-lab/backend db:make create_users_table
 *
 * RESULT:
 * - Creates a file like:
 *     backend/src/shared/db/migrations/0001_create_users_table.ts
 */

import fs from 'node:fs';
import path from 'node:path';

function normalizeMigrationName(input: string): string {
  // Converts: "Create Users Table" -> "create_users_table"
  return input
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_]/g, '');
}

function getNextMigrationNumber(existingFiles: string[]): string {
  // Looks for files like "0001_....ts", "0002_....ts"
  const numbers = existingFiles
    .map((file) => file.match(/^(\d{4})_/))
    .filter((m): m is RegExpMatchArray => Boolean(m))
    .map((m) => Number(m[1]));

  const max = numbers.length ? Math.max(...numbers) : 0;
  return String(max + 1).padStart(4, '0');
}

function buildMigrationFileContents(fileName: string): string {
  // This is simply the TEXT we write into the new migration file.
  return `/**
 * src/shared/db/migrations/${fileName}
 *
 * WHY:
 * - Migration files are the single source of truth for DB schema changes.
 *
 * HOW TO USE:
 * - Run all migrations:
 *     yarn db:migrate
 */

import { Kysely } from "kysely";

export async function up(db: Kysely<any>): Promise<void> {
  // TODO: implement schema changes
}

export async function down(db: Kysely<any>): Promise<void> {
  // TODO: revert schema changes
}
`;
}

async function main(): Promise<void> {
  const rawName = process.argv[2];

  if (!rawName) {
    console.error('❌ Missing migration name.');
    console.error('Example: yarn workspace @auth-lab/backend db:make create_users_table');
    process.exit(1);
  }

  const safeName = normalizeMigrationName(rawName);

  // We run this script from backend/ (because the package script runs there),
  // so process.cwd() is backend/.
  const migrationsDir = path.join(process.cwd(), 'src/shared/db/migrations');

  if (!fs.existsSync(migrationsDir)) {
    fs.mkdirSync(migrationsDir, { recursive: true });
  }

  const existingFiles = fs.readdirSync(migrationsDir);
  const nextNumber = getNextMigrationNumber(existingFiles);

  const fileName = `${nextNumber}_${safeName}.ts`;
  const fullPath = path.join(migrationsDir, fileName);

  if (fs.existsSync(fullPath)) {
    console.error(`❌ Migration already exists: ${fileName}`);
    process.exit(1);
  }

  const fileContents = buildMigrationFileContents(fileName);
  fs.writeFileSync(fullPath, fileContents, 'utf8');

  console.log(`✅ Created migration: ${fullPath}`);
}

void main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
