/**
 * src/modules/users/use-cases/find-or-create-user.ts
 *
 * WHY:
 * - Multiple flows need "find-or-create user by email": registration,
 *   SSO login, and public signup (Brick 11).
 * - Centralizing prevents drift in the insert-then-reread pattern and
 *   ensures email normalization is applied consistently everywhere.
 *
 * WHAT IT DOES:
 * - If a User with the given (normalized) email already exists → return it.
 * - Otherwise → insert a new User and return the constructed domain type.
 *
 * RULES:
 * - Receives a trx-bound executor. Caller owns the transaction.
 * - Email MUST already be normalized to lowercase before calling.
 * - Does NOT write audit events — caller owns the audit context.
 * - No AppError thrown here; failures surface as raw DB errors (e.g. unique violation).
 *
 * BRICK 11 UPDATE:
 * - Added optional emailVerifiedForNewUser param.
 * - Only applied when a new user row is inserted (userCreated: true).
 * - When the user already exists (userCreated: false), emailVerifiedForNewUser
 *   is ignored — the existing user's email_verified status is unchanged.
 * - All existing callers omit this param; DB default (true) applies to them.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { UserRepo } from '../dal/user.repo';
import type { User } from '../user.types';
import { getUserByEmail } from '../queries/user.queries';

export type FindOrCreateUserResult = {
  user: User;
  /** True when a new user row was inserted; false when the user already existed. */
  userCreated: boolean;
};

export async function findOrCreateUser(params: {
  trx: DbExecutor;
  userRepo: UserRepo;
  email: string;
  name: string | null;
  now: Date;
  /**
   * email_verified value for newly inserted users.
   *
   * Omit (or pass undefined) for all existing flows — DB default (true) applies.
   * Pass false only when the caller needs the new user to go through email
   * verification (i.e. public password signup in Brick 11).
   *
   * Ignored when the user already exists (userCreated: false).
   */
  emailVerifiedForNewUser?: boolean;
}): Promise<FindOrCreateUserResult> {
  const { trx, userRepo, email, name, now, emailVerifiedForNewUser } = params;

  const existing = await getUserByEmail(trx, email);
  if (existing) {
    return { user: existing, userCreated: false };
  }

  const inserted = await userRepo.insertUser({
    email,
    name,
    // Only forward when explicitly false — omit otherwise so DB default applies.
    ...(emailVerifiedForNewUser === false ? { emailVerified: false } : {}),
  });

  const user: User = {
    id: inserted.id,
    email: inserted.email,
    name,
    // Reflect what was actually stored.
    emailVerified: emailVerifiedForNewUser === false ? false : true,
    createdAt: now,
    updatedAt: now,
  };

  return { user, userCreated: true };
}
