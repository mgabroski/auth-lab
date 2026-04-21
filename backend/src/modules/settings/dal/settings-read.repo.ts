/**
 * backend/src/modules/settings/dal/settings-read.repo.ts
 *
 * WHY:
 * - Aggregates the low-level read queries needed by the Phase 2 bootstrap and
 *   overview surfaces.
 * - Keeps tenant truth, persisted Settings state, and optional CP producer
 *   snapshot loading out of the higher-level composition services.
 *
 * RULES:
 * - Read-only.
 * - No AppError.
 * - No state recomputation here.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { Tenant } from '../../tenants/tenant.types';
import { getTenantById } from '../../tenants/queries/tenant.queries';
import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';
import {
  loadAccountSnapshot,
  snapshotToAccountDetail,
} from '../../control-plane/accounts/cp-accounts.domain';
import { SettingsFoundationRepo } from './settings-foundation.repo';
import type { SettingsStateBundle } from '../settings.types';

export class SettingsReadRepo {
  private readonly foundationRepo: SettingsFoundationRepo;

  constructor(private readonly db: DbExecutor) {
    this.foundationRepo = new SettingsFoundationRepo(db);
  }

  withDb(db: DbExecutor): SettingsReadRepo {
    return new SettingsReadRepo(db);
  }

  async getTenant(tenantId: string): Promise<Tenant | undefined> {
    return getTenantById(this.db, tenantId);
  }

  async getStateBundle(tenantId: string): Promise<SettingsStateBundle | undefined> {
    return this.foundationRepo.getStateBundle(tenantId);
  }

  async getCpHandoffByTenantId(tenantId: string): Promise<CpSettingsHandoffSnapshot | undefined> {
    const row = await this.db
      .selectFrom('cp_account_provisioning as provisioning')
      .innerJoin('cp_accounts as account', 'account.id', 'provisioning.account_id')
      .select('account.account_key as account_key')
      .where('provisioning.tenant_id', '=', tenantId)
      .executeTakeFirst();

    if (!row) {
      return undefined;
    }

    const snapshot = await loadAccountSnapshot(this.db, row.account_key);
    return snapshotToAccountDetail(snapshot).settingsHandoff;
  }
}
