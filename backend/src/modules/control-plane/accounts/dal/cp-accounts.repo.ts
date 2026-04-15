/**
 * backend/src/modules/control-plane/accounts/dal/cp-accounts.repo.ts
 *
 * WHY:
 * - DAL WRITES ONLY for cp_accounts.
 * - Mutation methods only. Reads live in cp-accounts.query-sql.ts.
 *
 * RULES:
 * - No AppError.
 * - No policies.
 * - No transactions started here — service owns the transaction boundary.
 * - withDb() supports passing a transaction executor from the service.
 *
 * CP REVISION:
 * - insertAccount sets cp_revision = 0 on creation.
 * - Future group-save and publish methods will call incrementRevision().
 *   Those methods are deferred to later phases.
 */

import type { DbExecutor } from '../../../../shared/db/db';

export type InsertCpAccountParams = {
  accountName: string;
  accountKey: string;
};

export type InsertCpAccountResult = {
  id: string;
  accountKey: string;
  createdAt: Date;
};

export class CpAccountsRepo {
  constructor(private readonly db: DbExecutor) {}

  /**
   * Returns a repo bound to a different executor (e.g. a transaction).
   * Follows the withDb() pattern used across this repo's DAL layer.
   */
  withDb(db: DbExecutor): CpAccountsRepo {
    return new CpAccountsRepo(db);
  }

  /**
   * Inserts a new cp_accounts row with status='Draft' and cp_revision=0.
   * Returns the generated id, accountKey, and createdAt.
   *
   * The caller must guard against UNIQUE constraint violations on account_key
   * (service checks existence before insert; DB constraint is the last line).
   */
  async insertAccount(params: InsertCpAccountParams): Promise<InsertCpAccountResult> {
    const row = await this.db
      .insertInto('cp_accounts')
      .values({
        account_name: params.accountName,
        account_key: params.accountKey,
        cp_status: 'Draft',
        cp_revision: 0,
      })
      .returning(['id', 'account_key', 'created_at'])
      .executeTakeFirstOrThrow();

    return {
      id: row.id,
      accountKey: row.account_key,
      createdAt: row.created_at,
    };
  }
}
