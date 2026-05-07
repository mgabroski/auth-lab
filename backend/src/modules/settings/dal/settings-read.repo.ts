/**
 * backend/src/modules/settings/dal/settings-read.repo.ts
 *
 * WHY:
 * - Aggregates the low-level read queries needed by the Settings bootstrap,
 *   overview, section, and CP handoff read surfaces.
 * - Keeps tenant truth, persisted Settings state, and the published CP handoff
 *   read boundary out of the higher-level composition services.
 *
 * RULES:
 * - Read-only.
 * - No AppError.
 * - No state recomputation here.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { Tenant } from '../../tenants/tenant.types';
import { getTenantById } from '../../tenants/queries/tenant.queries';
import type {
  CpSettingsHandoffReader,
  CpSettingsHandoffSnapshot,
} from '../../control-plane/accounts';
import { SettingsFoundationRepo } from './settings-foundation.repo';
import type { SettingsStateBundle } from '../settings.types';

export type CpSettingsHandoffReaderFactory = (db: DbExecutor) => CpSettingsHandoffReader;

export class SettingsReadRepo {
  private readonly foundationRepo: SettingsFoundationRepo;

  private readonly cpHandoffReader: CpSettingsHandoffReader;

  constructor(
    private readonly db: DbExecutor,
    private readonly cpHandoffReaderFactory: CpSettingsHandoffReaderFactory,
  ) {
    this.foundationRepo = new SettingsFoundationRepo(db);
    this.cpHandoffReader = cpHandoffReaderFactory(db);
  }

  withDb(db: DbExecutor): SettingsReadRepo {
    return new SettingsReadRepo(db, this.cpHandoffReaderFactory);
  }

  async getTenant(tenantId: string): Promise<Tenant | undefined> {
    return getTenantById(this.db, tenantId);
  }

  async getStateBundle(tenantId: string): Promise<SettingsStateBundle | undefined> {
    return this.foundationRepo.getStateBundle(tenantId);
  }

  async getCpHandoffByTenantId(tenantId: string): Promise<CpSettingsHandoffSnapshot | undefined> {
    return this.cpHandoffReader.getByTenantId(tenantId);
  }
}
