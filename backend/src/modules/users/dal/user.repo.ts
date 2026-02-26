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
   * Creates a new user. If a user with the same email already exists (concurrent
   * or sequential), the existing user is returned — no error is thrown.
   *
   * Pattern: INSERT … ON CONFLICT (email) DO NOTHING RETURNING.
   * If RETURNING is empty (conflict), the existing row is re-read in the same
   * db/tx scope. Callers receive the correct user in all cases.
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
    const normalizedEmail = params.email.toLowerCase();

    const values: {
      email: string;
      name: string | null;
      email_verified?: boolean;
    } = {
      email: normalizedEmail,
      name: params.name,
    };

    // Only include email_verified when explicitly set to false.
    // All other callers omit it and let the DB default (true) apply.
    if (params.emailVerified === false) {
      values.email_verified = false;
    }

    // ── INSERT … ON CONFLICT DO NOTHING (concurrency-safe) ───────────────
    // executeTakeFirst (not OrThrow) — a conflict returns undefined, not an error.
    const inserted = await this.db
      .insertInto('users')
      .values(values)
      .onConflict((oc) => oc.column('email').doNothing())
      .returning(['id', 'email'])
      .executeTakeFirst();

    if (inserted) {
      return { id: inserted.id, email: inserted.email };
    }

    // ── Conflict occurred: concurrent request created this user first ─────
    // Re-read within the same db/tx scope. This is safe and atomic:
    // the user MUST exist now (it caused our conflict), so executeTakeFirstOrThrow
    // is correct here — if it throws something else is very wrong.
    const existing = await this.db
      .selectFrom('users')
      .select(['id', 'email'])
      .where('email', '=', normalizedEmail)
      .executeTakeFirstOrThrow();

    return { id: existing.id, email: existing.email };
  }
}
