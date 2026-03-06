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
   * Creates an SSO auth identity for a user. If one already exists for the same
   * (user_id, provider) pair — which can happen with concurrent OAuth callbacks —
   * the existing identity is returned and no error is thrown.
   *
   * Pattern: INSERT … ON CONFLICT (user_id, provider) DO NOTHING RETURNING.
   * If RETURNING is empty (conflict), the existing row is re-read in the same
   * db/tx scope. (DDIA: correctness under concurrency is non-negotiable.)
   */
  async insertSsoIdentity(input: {
    userId: string;
    provider: 'google' | 'microsoft';
    providerSubject: string;
  }): Promise<{ id: string }> {
    const inserted = await this.db
      .insertInto('auth_identities')
      .values({
        user_id: input.userId,
        provider: input.provider,
        provider_subject: input.providerSubject,
        password_hash: null,
      })
      .onConflict((oc) => oc.columns(['user_id', 'provider']).doNothing())
      .returning(['id'])
      .executeTakeFirst();

    if (inserted) {
      return { id: inserted.id };
    }

    const existing = await this.db
      .selectFrom('auth_identities')
      .select(['id'])
      .where('user_id', '=', input.userId)
      .where('provider', '=', input.provider)
      .executeTakeFirstOrThrow();

    return { id: existing.id };
  }

  /**
   * Atomically consumes one valid reset token.
   *
   * Returns the owning user when the token was active and is now consumed.
   * Returns null when the token is missing, expired, or already used.
   */
  async consumeResetTokenAtomic(params: {
    tokenHash: string;
    now: Date;
  }): Promise<{ userId: string } | null> {
    const row = await this.db
      .updateTable('password_reset_tokens')
      .set({ used_at: params.now })
      .where('token_hash', '=', params.tokenHash)
      .where('used_at', 'is', null)
      .where('expires_at', '>', params.now)
      .returning(['user_id'])
      .executeTakeFirst();

    if (!row) return null;
    return { userId: row.user_id };
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
}
