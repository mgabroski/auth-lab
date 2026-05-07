/**
 * backend/src/modules/control-plane/accounts/cp-settings-handoff.reader.ts
 *
 * WHY:
 * - Publishes the CP-owned Settings handoff read boundary for sibling modules.
 * - Keeps Settings from importing CP internals such as cp-accounts.domain or
 *   handoff builder/type files directly.
 *
 * RULES:
 * - This file is the public CP Accounts read adapter for Settings.
 * - CP internals may be used here because this file lives inside the CP module.
 * - Consumers depend on the interface exported from accounts/index.ts.
 */

import type { DbExecutor } from '../../../shared/db/db';
import { loadAccountSnapshot, snapshotToAccountDetail } from './cp-accounts.domain';
import type { CpSettingsHandoffSnapshot } from './handoff/cp-settings-handoff.types';

export type CpSettingsHandoffReader = {
  getByTenantId(tenantId: string): Promise<CpSettingsHandoffSnapshot | undefined>;
};

export class SqlCpSettingsHandoffReader implements CpSettingsHandoffReader {
  constructor(private readonly db: DbExecutor) {}

  async getByTenantId(tenantId: string): Promise<CpSettingsHandoffSnapshot | undefined> {
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

export function createCpSettingsHandoffReader(db: DbExecutor): CpSettingsHandoffReader {
  return new SqlCpSettingsHandoffReader(db);
}
