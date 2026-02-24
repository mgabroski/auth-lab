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
}): Promise<FindOrCreateUserResult> {
  const { trx, userRepo, email, name, now } = params;

  const existing = await getUserByEmail(trx, email);
  if (existing) {
    return { user: existing, userCreated: false };
  }

  const inserted = await userRepo.insertUser({ email, name });

  const user: User = {
    id: inserted.id,
    email: inserted.email,
    name,
    createdAt: now,
    updatedAt: now,
  };

  return { user, userCreated: true };
}
