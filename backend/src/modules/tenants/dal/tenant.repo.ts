/**
 * backend/src/modules/tenants/dal/tenant.repo.ts
 *
 * WHY:
 * - DAL WRITES ONLY for tenants (mutations).
 *
 * RULES:
 * - No transactions started here (service owns tx).
 * - No AppError.
 * - No policies.
 * - Supports withDb() for transaction binding (same pattern as AuditRepo, InviteRepo).
 */

import type { DbExecutor } from '../../../shared/db/db';

export class TenantRepo {
  constructor(private readonly db: DbExecutor) {}

  /**
   * Returns a repo bound to a different executor (e.g. a transaction).
   * This keeps the "repo instance" pattern while supporting trx usage.
   */
  withDb(db: DbExecutor): TenantRepo {
    return new TenantRepo(db);
  }

  // Intentionally empty in Brick 5.
  // Writes will be added as tenant management features land.
}
