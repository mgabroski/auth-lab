/**
 * backend/src/modules/users/dal/user.query-sql.ts
 *
 * WHY:
 * - DAL READS ONLY for users (raw SQL access).
 * - Users are global identities — queries are NOT tenant-scoped.
 *
 * RULES:
 * - No AppError.
 * - No policies.
 * - No transactions started here.
 */

import type { Selectable } from 'kysely';
import type { DbExecutor } from '../../../shared/db/db';
import type { Users } from '../../../shared/db/database.types';

export type UserRow = Selectable<Users>;

export async function selectUserByEmailSql(
  db: DbExecutor,
  email: string,
): Promise<UserRow | undefined> {
  return db
    .selectFrom('users')
    .selectAll()
    .where('email', '=', email.toLowerCase())
    .executeTakeFirst();
}

export async function selectUserByIdSql(
  db: DbExecutor,
  userId: string,
): Promise<UserRow | undefined> {
  return db.selectFrom('users').selectAll().where('id', '=', userId).executeTakeFirst();
}
