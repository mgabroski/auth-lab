/**
 * backend/src/modules/control-plane/accounts/cp-accounts.service.ts
 *
 * WHY:
 * - Business orchestration for CP accounts.
 * - Owns the create → uniqueness-guard → insert sequence.
 * - Maps DAL row shape to domain type (CpAccount / CpAccountListRow).
 *
 * RULES:
 * - No raw DB access. All DB calls go through repo or query-sql functions.
 * - Throws AppError (via CpAccountErrors) for domain failures.
 * - No HTTP concerns here (no FastifyRequest / FastifyReply).
 *
 * PHASE 2 SCOPE:
 * - createAccount   — POST /cp/accounts
 * - getAccount      — GET  /cp/accounts/:accountKey
 * - listAccounts    — GET  /cp/accounts
 *
 * DEFERRED (later phases):
 * - Group saves (PUT /cp/accounts/:accountKey/access etc.)
 * - Publish (POST /cp/accounts/:accountKey/publish)
 * - Status toggle (PATCH /cp/accounts/:accountKey/status)
 * - cpRevision increment on group mutations
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { Logger } from '../../../shared/logger/logger';
import type { CpAccount, CpAccountListRow, CpStatus } from './cp-accounts.types';
import type { CreateCpAccountInput } from './cp-accounts.schemas';
import type { CpAccountsRepo } from './dal/cp-accounts.repo';
import type { CpAccountRow } from './dal/cp-accounts.query-sql';
import { findCpAccountByKeySql, listCpAccountsSql } from './dal/cp-accounts.query-sql';
import { CpAccountErrors } from './cp-accounts.errors';

function rowToAccount(row: CpAccountRow): CpAccount {
  return {
    id: row.id,
    accountName: row.account_name,
    accountKey: row.account_key,
    cpStatus: row.cp_status as CpStatus,
    cpRevision: row.cp_revision,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function rowToListRow(row: CpAccountRow): CpAccountListRow {
  return {
    id: row.id,
    accountName: row.account_name,
    accountKey: row.account_key,
    cpStatus: row.cp_status as CpStatus,
    cpRevision: row.cp_revision,
  };
}

export class CpAccountsService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      logger: Logger;
      cpAccountsRepo: CpAccountsRepo;
    },
  ) {}

  /**
   * Creates a new Draft CP account.
   *
   * Steps:
   * 1. Check accountKey uniqueness (service-layer guard before insert).
   * 2. Insert row with status=Draft, cpRevision=0.
   * 3. Return full CpAccount domain object.
   *
   * Throws CpAccountErrors.accountKeyConflict if the key is already taken.
   */
  async createAccount(input: CreateCpAccountInput): Promise<CpAccount> {
    const existing = await findCpAccountByKeySql(this.deps.db, input.accountKey);

    if (existing) {
      throw CpAccountErrors.accountKeyConflict(input.accountKey);
    }

    const { id, accountKey, createdAt } = await this.deps.cpAccountsRepo.insertAccount({
      accountName: input.accountName,
      accountKey: input.accountKey,
    });

    this.deps.logger.info('cp.accounts.created', {
      event: 'cp.accounts.created',
      accountKey,
      id,
    });

    // Re-fetch the full row so the returned object is consistent with getAccount().
    const row = await findCpAccountByKeySql(this.deps.db, accountKey);

    if (!row) {
      // Should never happen — insert succeeded and we hold the key.
      throw new Error(`cp.accounts: post-insert read failed for key=${accountKey} id=${id}`);
    }

    void createdAt; // used for log; row.created_at is authoritative
    return rowToAccount(row);
  }

  /**
   * Returns a single CP account by its accountKey.
   * Throws CpAccountErrors.notFound if no such account exists.
   */
  async getAccount(accountKey: string): Promise<CpAccount> {
    const row = await findCpAccountByKeySql(this.deps.db, accountKey);

    if (!row) {
      throw CpAccountErrors.notFound(accountKey);
    }

    return rowToAccount(row);
  }

  /**
   * Returns all CP accounts as slim list rows, ordered by created_at asc.
   */
  async listAccounts(): Promise<CpAccountListRow[]> {
    const rows = await listCpAccountsSql(this.deps.db);
    return rows.map(rowToListRow);
  }
}
