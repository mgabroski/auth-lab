/**
 * src/modules/auth/dal/mfa.query-sql.ts
 *
 * WHY:
 * - Read-only SQL queries for MFA data.
 * - Separated from repo (writes) per architecture rules.
 *
 * RULES:
 * - Read-only. No mutations.
 * - No AppError.
 * - Returns raw DB rows; shaping to domain types happens in mfa.queries.ts.
 */

import type { DbExecutor } from '../../../shared/db/db';

export async function selectMfaSecretByUser(
  db: DbExecutor,
  userId: string,
): Promise<{
  id: string;
  userId: string;
  secretEncrypted: string;
  isVerified: boolean;
  createdAt: Date;
  verifiedAt: Date | null;
} | null> {
  const row = await db
    .selectFrom('mfa_secrets')
    .select(['id', 'user_id', 'encrypted_secret', 'is_verified', 'created_at', 'verified_at'])
    .where('user_id', '=', userId)
    .executeTakeFirst();

  if (!row) return null;

  return {
    id: row.id,
    userId: row.user_id,
    secretEncrypted: row.encrypted_secret,
    isVerified: row.is_verified,
    createdAt: row.created_at instanceof Date ? row.created_at : new Date(row.created_at),
    verifiedAt:
      row.verified_at != null
        ? row.verified_at instanceof Date
          ? row.verified_at
          : new Date(row.verified_at)
        : null,
  };
}
