/**
 * src/modules/auth/queries/email-verification.queries.ts
 *
 * WHY:
 * - Queries are read-only, side-effect free, and shape DB rows into domain types.
 * - Mirrors auth.queries.ts pattern for password reset tokens.
 *
 * RULES:
 * - Read-only.
 * - No AppError.
 * - No transactions.
 */

import type { DbExecutor } from '../../../shared/db/db';
import { selectValidVerificationTokenSql } from '../dal/email-verification.query-sql';
import type { EmailVerificationToken } from '../auth.types';

/**
 * Returns a valid (not-yet-used, not-expired) email verification token by hash.
 * Returns undefined if the token is missing, expired, or already used.
 *
 * The three failure cases are collapsed into a single undefined intentionally
 * to prevent an oracle attack (same rationale as getValidResetToken).
 */
export async function getValidVerificationToken(
  db: DbExecutor,
  tokenHash: string,
): Promise<EmailVerificationToken | undefined> {
  const row = await selectValidVerificationTokenSql(db, tokenHash);
  if (!row) return undefined;

  return {
    id: row.id,
    userId: row.user_id,
    tokenHash: row.token_hash,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}
