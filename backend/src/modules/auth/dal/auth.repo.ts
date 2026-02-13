/**
 * src/modules/auth/dal/auth.repo.ts
 *
 * WHY:
 * - DAL WRITES ONLY for auth_identities and password_reset_tokens (mutations).
 * - Unique constraint (user_id, provider) enforced by DB on auth_identities.
 * - Token uniqueness enforced by unique index on password_reset_tokens(token_hash).
 *
 * RULES:
 * - No transactions started here (service owns tx).
 * - No AppError.
 * - No policies.
 * - Supports withDb() for transaction binding.
 */

import type { DbExecutor } from '../../../shared/db/db';

export class AuthRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): AuthRepo {
    return new AuthRepo(db);
  }

  // ── auth_identities ──────────────────────────────────────────

  /**
   * Creates a password auth identity for a user.
   * DB constraint: unique (user_id, provider).
   * DB constraint: password identity must have password_hash.
   */
  async insertPasswordIdentity(params: {
    userId: string;
    passwordHash: string;
  }): Promise<{ id: string }> {
    const row = await this.db
      .insertInto('auth_identities')
      .values({
        user_id: params.userId,
        provider: 'password',
        password_hash: params.passwordHash,
        provider_subject: null,
      })
      .returning(['id'])
      .executeTakeFirstOrThrow();

    return { id: row.id };
  }

  /**
   * Updates the password hash for a user's password identity.
   * Called after a successful password reset.
   */
  async updatePasswordHash(params: { userId: string; newHash: string }): Promise<void> {
    await this.db
      .updateTable('auth_identities')
      .set({
        password_hash: params.newHash,
        updated_at: new Date(),
      })
      .where('user_id', '=', params.userId)
      .where('provider', '=', 'password')
      .execute();
  }

  // ── password_reset_tokens ────────────────────────────────────

  /**
   * Inserts a new password reset token (hash only — raw token never stored).
   */
  async insertPasswordResetToken(params: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
  }): Promise<{ id: string }> {
    const row = await this.db
      .insertInto('password_reset_tokens')
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
   * Marks ALL active (used_at IS NULL) reset tokens for a user as used.
   *
   * Called in two places:
   * 1. BEFORE inserting a new token: enforces one-active-at-a-time.
   *    SECURITY TRADEOFF: An attacker who knows the victim's email can spam
   *    forgot-password (within rate limit: 3/hour) to invalidate the real
   *    user's most recent link. This is accepted behaviour — it mirrors
   *    GitHub/Google/AWS and is mitigated by the rate limit. The alternative
   *    (multiple active tokens) means leaked old tokens remain exploitable.
   * 2. AFTER consuming a token: cleans up any parallel tokens issued in the
   *    same window (e.g., user clicked "resend" twice in quick succession).
   */
  async invalidateActiveResetTokensForUser(params: { userId: string }): Promise<void> {
    await this.db
      .updateTable('password_reset_tokens')
      .set({ used_at: new Date() })
      .where('user_id', '=', params.userId)
      .where('used_at', 'is', null)
      .execute();
  }

  /**
   * Marks a single specific token as used (by its token_hash).
   * Called immediately after a successful password reset to consume the token.
   */
  async markResetTokenUsed(params: { tokenHash: string }): Promise<void> {
    await this.db
      .updateTable('password_reset_tokens')
      .set({ used_at: new Date() })
      .where('token_hash', '=', params.tokenHash)
      .execute();
  }
}
