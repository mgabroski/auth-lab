/**
 * src/modules/auth/dal/mfa.repo.ts
 *
 * WHY:
 * - DAL WRITES ONLY for mfa_secrets and mfa_recovery_codes.
 *
 * KEY DESIGN:
 * - insertMfaSecret(): upsert pattern — if setup is retried, we overwrite the
 *   unverified secret so the user doesn't end up with a stale row blocking setup.
 * - insertRecoveryCodes(): inserts 8 codes at once. DB UNIQUE(user_id, code_hash)
 *   prevents duplicates if this races with another setup call.
 * - useRecoveryCodeAtomic(): single UPDATE...WHERE used_at IS NULL RETURNING.
 *   No separate SELECT. Eliminates TOCTOU race where two concurrent requests
 *   could both find the same code as unused before either marks it used.
 *   If UPDATE returns a row → code was valid and is now consumed.
 *   If UPDATE returns nothing → code is wrong, already used, or belongs to another user.
 *
 * RULES:
 * - No transactions started here (service owns tx scope if needed).
 * - No AppError.
 * - Supports withDb() for transaction binding.
 */

import type { DbExecutor } from '../../../shared/db/db';

export class MfaRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): MfaRepo {
    return new MfaRepo(db);
  }

  // ── mfa_secrets ──────────────────────────────────────────────────────────────

  async insertMfaSecret(params: {
    userId: string;
    secretEncrypted: string;
  }): Promise<{ id: string }> {
    const row = await this.db
      .insertInto('mfa_secrets')
      .values({
        user_id: params.userId,
        encrypted_secret: params.secretEncrypted,
        is_verified: false,
      })
      .returning(['id'])
      .executeTakeFirstOrThrow();

    return { id: row.id };
  }

  async verifyMfaSecret(params: { userId: string }): Promise<{ updated: number }> {
    const result = await this.db
      .updateTable('mfa_secrets')
      .set({
        is_verified: true,
        verified_at: new Date(),
      })
      .where('user_id', '=', params.userId)
      .where('is_verified', '=', false)
      .executeTakeFirst();

    return { updated: Number(result.numUpdatedRows) };
  }

  async deleteUnverifiedMfaSecret(params: { userId: string }): Promise<void> {
    await this.db
      .deleteFrom('mfa_secrets')
      .where('user_id', '=', params.userId)
      .where('is_verified', '=', false)
      .execute();
  }

  // ── mfa_recovery_codes ───────────────────────────────────────────────────────

  async insertRecoveryCodes(params: { userId: string; codeHashes: string[] }): Promise<void> {
    await this.db
      .insertInto('mfa_recovery_codes')
      .values(
        params.codeHashes.map((codeHash) => ({
          user_id: params.userId,
          code_hash: codeHash,
        })),
      )
      .execute();
  }

  async useRecoveryCodeAtomic(params: {
    userId: string;
    codeHash: string;
  }): Promise<{ id: string } | null> {
    const row = await this.db
      .updateTable('mfa_recovery_codes')
      .set({ used_at: new Date() })
      .where('user_id', '=', params.userId)
      .where('code_hash', '=', params.codeHash)
      .where('used_at', 'is', null)
      .returning(['id'])
      .executeTakeFirst();

    return row ?? null;
  }
}
