/**
 * backend/src/modules/auth/dal/email-verification.query-sql.ts
 *
 * WHY:
 * - DAL READS ONLY for email_verification_tokens.
 * - Follows the same split as auth.query-sql.ts: reads here, writes in repo.
 *
 * RULES:
 * - No AppError.
 * - No policies.
 * - No transactions started here.
 * - WHERE clause for "valid token" (Decision from brief): used_at IS NULL AND
 *   expires_at > now() — locked to match the invalidation query precisely.
 */

import type { Selectable } from 'kysely';
import type { DbExecutor } from '../../../shared/db/db';
import type { EmailVerificationTokens } from '../../../shared/db/database.types';
import { sql } from 'kysely';

export type EmailVerificationTokenRow = Selectable<EmailVerificationTokens>;

/**
 * Returns a token row that is:
 *   - not consumed (used_at IS NULL)
 *   - not expired (expires_at > now())
 *
 * Returns undefined if the token is missing, expired, or already used.
 * A single undefined covers all three cases — no oracle (same rationale as reset tokens).
 */
export async function selectValidVerificationTokenSql(
  db: DbExecutor,
  tokenHash: string,
): Promise<EmailVerificationTokenRow | undefined> {
  return db
    .selectFrom('email_verification_tokens')
    .selectAll()
    .where('token_hash', '=', tokenHash)
    .where('used_at', 'is', null)
    .where('expires_at', '>', sql<Date>`now()`)
    .executeTakeFirst();
}
