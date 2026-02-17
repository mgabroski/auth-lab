/**
 * src/shared/db/migrations/0006_mfa_tables.ts
 *
 * WHY:
 * - Brick 9 (MFA / TOTP) requires two new tables:
 *   - mfa_secrets: stores the encrypted TOTP secret per user.
 *   - mfa_recovery_codes: stores HMAC-SHA256-hashed single-use recovery codes.
 *
 * KEY CONSTRAINTS:
 * - mfa_secrets: UNIQUE(user_id) — one secret per user globally.
 *   The secret is shared across all tenants (same user model = one identity globally).
 * - mfa_recovery_codes: UNIQUE(user_id, code_hash) — prevents duplicate hashes
 *   per user even if setup is retried or concurrent setup calls race.
 *
 * HOW TO RUN:
 *   yarn db:migrate
 */

import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    CREATE TABLE mfa_secrets (
      id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      encrypted_secret TEXT        NOT NULL,
      issuer           TEXT        NOT NULL DEFAULT 'Hubins',
      is_verified      BOOLEAN     NOT NULL DEFAULT false,
      created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
      verified_at      TIMESTAMPTZ,
      UNIQUE (user_id)
    );
  `.execute(db);

  await sql`
    CREATE TABLE mfa_recovery_codes (
      id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      code_hash  TEXT        NOT NULL,
      used_at    TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE (user_id, code_hash)
    );
  `.execute(db);

  await sql`
    CREATE INDEX idx_mfa_recovery_user ON mfa_recovery_codes (user_id);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`DROP INDEX IF EXISTS idx_mfa_recovery_user;`.execute(db);
  await sql`DROP TABLE IF EXISTS mfa_recovery_codes;`.execute(db);
  await sql`DROP TABLE IF EXISTS mfa_secrets;`.execute(db);
}
