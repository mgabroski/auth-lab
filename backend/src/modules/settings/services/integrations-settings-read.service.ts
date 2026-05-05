/**
 * backend/src/modules/settings/services/integrations-settings-read.service.ts
 *
 * WHY:
 * - Owns the real read DTO behind `GET /settings/integrations`.
 * - Loads tenant-scoped Settings state and CP handoff truth, then delegates
 *   SSO/deferred integration composition to the query service.
 *
 * RULES:
 * - Read-only.
 * - No write/audit behavior.
 * - No live provider calls.
 */

import { SettingsReadRepo } from '../dal/settings-read.repo';
import type { IntegrationsSettingsDto } from '../settings.types';
import { IntegrationsSettingsQueryService } from './integrations-settings-query.service';
import { deriveSettingsNextAction } from './settings-next-action';

export class IntegrationsSettingsReadService {
  constructor(
    private readonly readRepo: SettingsReadRepo,
    private readonly integrationsQuery: IntegrationsSettingsQueryService,
  ) {}

  async getIntegrationsSettings(tenantId: string): Promise<IntegrationsSettingsDto> {
    const [state, tenant, cpHandoff] = await Promise.all([
      this.readRepo.getStateBundle(tenantId),
      this.readRepo.getTenant(tenantId),
      this.readRepo.getCpHandoffByTenantId(tenantId),
    ]);

    if (!state) {
      throw new Error(`Settings foundation rows not found for tenant ${tenantId}`);
    }

    if (!tenant) {
      throw new Error(`Tenant not found for integrations settings: ${tenantId}`);
    }

    const personalRequired = cpHandoff?.allowances.modules.modules.personal ?? true;
    const model = this.integrationsQuery.build({ tenant, cpHandoff });

    return this.integrationsQuery.toDto({
      status: state.sections.integrations.status,
      version: state.sections.integrations.version,
      cpRevision: state.sections.integrations.appliedCpRevision,
      nextAction: deriveSettingsNextAction({
        overallStatus: state.aggregate.overallStatus,
        accessStatus: state.sections.access.status,
        personalStatus: state.sections.personal.status,
        personalRequired,
      }),
      model,
    });
  }
}
