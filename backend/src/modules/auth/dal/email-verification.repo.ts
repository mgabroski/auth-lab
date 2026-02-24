/**
 * backend/src/modules/auth/dal/email-verification.repo.ts
 *
 * WHY:
 * - DAL WRITES ONLY for email_verification_tokens and users.email_verified.
 * - Keeps write operations separate from read queries (arch rule).
 *
 * RULES:
 * - No transactions started here (flows own transactions).
 * - No AppError.
 * - No policies.
 * - Supports withDb() for transaction binding.
 */

import type { DbExecutor } from '../../../shared/db/db';

export class EmailVerificationRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): EmailVerificationRepo {
    return new EmailVerificationRepo(db);
  }

  /**
   * Inserts a new email verification token (hash only — raw token never stored).
   */
  async insertVerificationToken(params: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
  }): Promise<{ id: string }> {
    const row = await this.db
      .insertInto('email_verification_tokens')
      .values({
        user_id: params.userId,
        token_hash: params.tokenHash,
        expires_at: params.expiresAt,
      })
      .returning(['id'])
      .executeTakeFirstOrThrow();

    return { id: row.id };
  }

  /**
   * Marks ALL active (used_at IS NULL, expires_at > now()) verification tokens
   * for a user as used.
   *
   * WHERE condition (locked — Decision from brief):
   *   user_id = ? AND used_at IS NULL AND expires_at > now()
   *
   * Called in two places:
   * 1. BEFORE inserting a new token: enforces one-active-at-a-time.
   * 2. AFTER consuming a token: cleans up any parallel tokens (e.g., user
   *    clicked "resend" twice in quick succession).
   *
   * WHY only active (not expired) tokens:
   * - Rewriting history of expired/used rows adds unnecessary writes.
   * - Skipping them keeps analytics/forensics clean.
   * - Expired tokens are already inert — they can never be consumed.
   */
  async invalidateActiveVerificationTokensForUser(params: { userId: string }): Promise<void> {
    await this.db
      .updateTable('email_verification_tokens')
      .set({ used_at: new Date() })
      .where('user_id', '=', params.userId)
      .where('used_at', 'is', null)
      .where('expires_at', '>', new Date())
      .execute();
  }

  /**
   * Marks a single specific verification token as used (by its token_hash).
   * Called immediately after a successful email verification to consume the token.
   */
  async markVerificationTokenUsed(params: { tokenHash: string }): Promise<void> {
    await this.db
      .updateTable('email_verification_tokens')
      .set({ used_at: new Date() })
      .where('token_hash', '=', params.tokenHash)
      .execute();
  }

  /**
   * Flips users.email_verified to true for a given user.
   * Called atomically within the same transaction as markVerificationTokenUsed.
   */
  async markUserEmailVerified(params: { userId: string }): Promise<void> {
    await this.db
      .updateTable('users')
      .set({ email_verified: true, updated_at: new Date() })
      .where('id', '=', params.userId)
      .execute();
  }
}
