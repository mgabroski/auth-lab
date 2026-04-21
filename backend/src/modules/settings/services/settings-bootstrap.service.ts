/**
 * backend/src/modules/settings/services/settings-bootstrap.service.ts
 *
 * WHY:
 * - Owns the bootstrap-safe Settings read surface used by /admin and future
 *   SSR consumers.
 * - Reads only persisted aggregate truth plus a minimal next-action pointer.
 * - Keeps the current auth scaffold from remaining the long-term owner of
 *   setup semantics.
 */

import { SettingsReadRepo } from '../dal/settings-read.repo';
import { type SettingsBootstrapDto } from '../settings.types';
import { deriveSettingsNextAction } from './settings-next-action';

export class SettingsBootstrapService {
  constructor(private readonly readRepo: SettingsReadRepo) {}

  async getBootstrap(tenantId: string): Promise<SettingsBootstrapDto> {
    const state = await this.readRepo.getStateBundle(tenantId);
    const cpHandoff = await this.readRepo.getCpHandoffByTenantId(tenantId);

    if (!state) {
      throw new Error(`Settings foundation rows not found for tenant ${tenantId}`);
    }

    const personalRequired = cpHandoff?.allowances.modules.modules.personal ?? true;
    const nextAction = deriveSettingsNextAction({
      overallStatus: state.aggregate.overallStatus,
      accessStatus: state.sections.access.status,
      personalStatus: state.sections.personal.status,
      personalRequired,
    });

    return {
      overallStatus: state.aggregate.overallStatus,
      showSetupBanner: state.aggregate.overallStatus !== 'COMPLETE',
      nextAction,
    };
  }
}
