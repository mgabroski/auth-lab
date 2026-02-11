/**
 * backend/src/modules/auth/dal/auth.query-sql.ts
 *
 * WHY:
 * - DAL READS ONLY for auth_identities (raw SQL access).
 * - Auth identities are user-scoped (not tenant-scoped).
 *
 * RULES:
 * - No AppError.
 * - No policies.
 * - No transactions started here.
 */

import type { Selectable } from 'kysely';
import type { DbExecutor } from '../../../shared/db/db';
import type { AuthIdentities } from '../../../shared/db/database.types';

export type AuthIdentityRow = Selectable<AuthIdentities>;

export async function selectAuthIdentityByUserAndProviderSql(
  db: DbExecutor,
  params: { userId: string; provider: string },
): Promise<AuthIdentityRow | undefined> {
  return db
    .selectFrom('auth_identities')
    .selectAll()
    .where('user_id', '=', params.userId)
    .where('provider', '=', params.provider)
    .executeTakeFirst();
}
