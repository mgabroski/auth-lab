/**
 * backend/src/modules/control-plane/accounts/dal/cp-accounts.query-sql.ts
 *
 * WHY:
 * - DAL READS ONLY for cp_accounts.
 * - Raw Kysely select statements; no business logic, no AppError, no policies.
 * - Service layer calls these directly (no separate queries.ts wrapper needed
 *   at this scale; add one if the query surface grows complex).
 *
 * RULES:
 * - No AppError.
 * - No policies.
 * - No transactions started here.
 * - Functions return undefined / empty array — never throw on "not found".
 */

import type { Selectable } from 'kysely';
import type { DbExecutor } from '../../../../shared/db/db';
import type { CpAccounts } from '../../../../shared/db/database.types';

export type CpAccountRow = Selectable<CpAccounts>;

/**
 * Returns the full cp_accounts row for the given accountKey,
 * or undefined if no such row exists.
 */
export async function findCpAccountByKeySql(
  db: DbExecutor,
  accountKey: string,
): Promise<CpAccountRow | undefined> {
  return db
    .selectFrom('cp_accounts')
    .selectAll()
    .where('account_key', '=', accountKey)
    .executeTakeFirst();
}

/**
 * Returns all cp_accounts rows ordered by creation time ascending.
 * Used by GET /cp/accounts list endpoint.
 */
export async function listCpAccountsSql(db: DbExecutor): Promise<CpAccountRow[]> {
  return db.selectFrom('cp_accounts').selectAll().orderBy('created_at', 'asc').execute();
}
