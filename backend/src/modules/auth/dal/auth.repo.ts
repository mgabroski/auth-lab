/**
 * backend/src/modules/auth/dal/auth.repo.ts
 *
 * WHY:
 * - DAL WRITES ONLY for auth_identities (mutations).
 * - Unique constraint (user_id, provider) enforced by DB.
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
}
