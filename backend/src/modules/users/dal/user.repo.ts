/**
 * backend/src/modules/users/dal/user.repo.ts
 *
 * WHY:
 * - DAL WRITES ONLY for users (mutations).
 * - Users are global identities — writes are NOT tenant-scoped.
 *
 * RULES:
 * - No transactions started here (service owns tx).
 * - No AppError.
 * - No policies.
 * - Supports withDb() for transaction binding.
 */

import type { DbExecutor } from '../../../shared/db/db';

export class UserRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): UserRepo {
    return new UserRepo(db);
  }

  /**
   * Creates a new user. Email must be globally unique (enforced by DB constraint).
   * Callers should catch unique-violation if doing find-or-create patterns.
   */
  async insertUser(params: {
    email: string;
    name: string | null;
  }): Promise<{ id: string; email: string }> {
    const row = await this.db
      .insertInto('users')
      .values({
        email: params.email.toLowerCase(),
        name: params.name,
      })
      .returning(['id', 'email'])
      .executeTakeFirstOrThrow();

    return { id: row.id, email: row.email };
  }
}
