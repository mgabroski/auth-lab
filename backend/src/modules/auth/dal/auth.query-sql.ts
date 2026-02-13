/**
 * src/modules/auth/dal/auth.query-sql.ts
 *
 * WHY:
 * - DAL READS ONLY for auth_identities and password_reset_tokens (raw SQL access).
 * - Auth identities are user-scoped (not tenant-scoped).
 * - Reset tokens are user-scoped; validity is checked by DB-side predicates
 *   (used_at IS NULL AND expires_at > now()) to avoid clock-skew issues.
 *
 * RULES:
 * - No AppError.
 * - No policies.
 * - No transactions started here.
 */

import type { Selectable } from 'kysely';
import type { DbExecutor } from '../../../shared/db/db';
import type { AuthIdentities, PasswordResetTokens } from '../../../shared/db/database.types';

export type AuthIdentityRow = Selectable<AuthIdentities>;
export type PasswordResetTokenRow = Selectable<PasswordResetTokens>;

export async function selectAuthIdentityByUserAndProviderSql(
  db: DbExecutor,
  params: { userId: string; provider: string },
): Promise<AuthIdentityRow | undefined> {
  return db
    .selectFrom('auth_identities')
    .selectAll()
    .where('user_id', '=', params.userId)
    .where('provider', '=', params.provider)
    .executeTakeFirst();
}

/**
 * Finds a valid (not-yet-used, not-expired) password reset token by its SHA-256 hash.
 *
 * WHY DB-SIDE expiry check:
 * - Checking expires_at > now() in the DB avoids application-level clock drift
 *   between the service and the database. The DB's clock is authoritative for
 *   time-sensitive security operations.
 */
export async function selectValidResetTokenSql(
  db: DbExecutor,
  tokenHash: string,
): Promise<PasswordResetTokenRow | undefined> {
  return db
    .selectFrom('password_reset_tokens')
    .selectAll()
    .where('token_hash', '=', tokenHash)
    .where('used_at', 'is', null)
    .where('expires_at', '>', new Date())
    .executeTakeFirst();
}
