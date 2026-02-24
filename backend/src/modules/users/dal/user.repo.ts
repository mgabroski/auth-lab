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
 *
 * BRICK 11 UPDATE:
 * - insertUser accepts an optional emailVerified param.
 * - When omitted: DB default (true) applies — all existing callers
 *   (invite registration, SSO) are unaffected.
 * - When explicitly false: sets email_verified = false for new users
 *   created via public password signup.
 * - Only the public signup flow ever passes emailVerified: false.
 *   All other callers omit it entirely.
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
   *
   * @param emailVerified - Optional. Omit to use DB default (true). Pass false only
   *   for public password signup where email verification is required (Brick 11).
   */
  async insertUser(params: {
    email: string;
    name: string | null;
    /** Defaults to DB default (true) when omitted. */
    emailVerified?: boolean;
  }): Promise<{ id: string; email: string }> {
    const values: {
      email: string;
      name: string | null;
      email_verified?: boolean;
    } = {
      email: params.email.toLowerCase(),
      name: params.name,
    };

    // Only include email_verified when explicitly set to false.
    // All other callers omit it and let the DB default (true) apply.
    if (params.emailVerified === false) {
      values.email_verified = false;
    }

    const row = await this.db
      .insertInto('users')
      .values(values)
      .returning(['id', 'email'])
      .executeTakeFirstOrThrow();

    return { id: row.id, email: row.email };
  }
}
