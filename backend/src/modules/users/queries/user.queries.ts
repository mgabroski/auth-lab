/**
 * backend/src/modules/users/queries/user.queries.ts
 *
 * WHY:
 * - Queries are read-only and side-effect free.
 * - They shape DB rows into User domain types.
 * - Users are global — no tenant scoping here.
 *
 * RULES:
 * - Read-only.
 * - No AppError.
 */

import type { DbExecutor } from '../../../shared/db/db';
import { selectUserByEmailSql, selectUserByIdSql } from '../dal/user.query-sql';
import type { UserRow } from '../dal/user.query-sql';
import type { User } from '../user.types';

function toUser(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    name: row.name ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function getUserByEmail(db: DbExecutor, email: string): Promise<User | undefined> {
  const row = await selectUserByEmailSql(db, email);
  if (!row) return undefined;
  return toUser(row);
}

export async function getUserById(db: DbExecutor, userId: string): Promise<User | undefined> {
  const row = await selectUserByIdSql(db, userId);
  if (!row) return undefined;
  return toUser(row);
}
