/**
 * backend/src/shared/db/migrations/0008_email_verification.ts
 *
 * WHY:
 * - Brick 11 (Public Signup) requires email verification for password-based
 *   self-service signups.
 * - Invite-based and SSO users are already identity-proven and must remain
 *   implicitly verified (DEFAULT true — Decision 1).
 * - Only the public signup flow explicitly passes email_verified = false
 *   when creating brand-new users.
 *
 * RULES:
 * - Additive migration only. No destructive changes.
 * - DEFAULT true on users.email_verified is intentional and locked.
 *   Changing it to false would break every existing user in Bricks 1–10.
 * - token_hash is UNIQUE: deterministic lookup, no duplicates.
 * - idx_email_verification_user on user_id: fast invalidation per user
 *   (invalidateVerificationTokensForUser scans this index).
 * - idx_email_verification_expires on expires_at: keeps future cleanup jobs
 *   cheap (delete expired rows without full-table scan).
 */

import type { Kysely } from 'kysely';
import { sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  // ── 1. Add email_verified column to users ──────────────────────────────
  // DEFAULT true: all users created before Brick 11 remain verified.
  // Only public signup explicitly sets this to false for new users.
  await db.schema
    .alterTable('users')
    .addColumn('email_verified', 'boolean', (col) => col.notNull().defaultTo(true))
    .execute();

  // ── 2. Create email_verification_tokens table ──────────────────────────
  await db.schema
    .createTable('email_verification_tokens')
    .addColumn('id', 'uuid', (col) => col.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn('user_id', 'uuid', (col) => col.notNull().references('users.id').onDelete('cascade'))
    .addColumn('token_hash', 'text', (col) => col.notNull())
    .addColumn('expires_at', 'timestamptz', (col) => col.notNull())
    .addColumn('used_at', 'timestamptz')
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addUniqueConstraint('email_verification_tokens_token_hash_unique', ['token_hash'])
    .execute();

  // ── 3. Indexes ──────────────────────────────────────────────────────────

  // Fast per-user invalidation (invalidateVerificationTokensForUser uses this)
  await db.schema
    .createIndex('idx_email_verification_user')
    .on('email_verification_tokens')
    .column('user_id')
    .execute();

  // Cheap future cleanup jobs — delete expired rows without full-table scan
  await db.schema
    .createIndex('idx_email_verification_expires')
    .on('email_verification_tokens')
    .column('expires_at')
    .execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.dropIndex('idx_email_verification_expires').execute();
  await db.schema.dropIndex('idx_email_verification_user').execute();
  await db.schema.dropTable('email_verification_tokens').execute();
  await db.schema.alterTable('users').dropColumn('email_verified').execute();
}
