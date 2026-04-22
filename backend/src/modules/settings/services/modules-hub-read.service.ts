/**
 * backend/src/modules/settings/services/modules-hub-read.service.ts
 *
 * WHY:
 * - Owns the real Modules hub read DTO behind `GET /settings/modules`.
 * - Composes persisted Personal section state with CP module allowance truth
 *   without inventing a hub-owned completion engine.
 */

import { SettingsReadRepo } from '../dal/settings-read.repo';
import type { ModulesHubDto } from '../settings.types';
import { deriveSettingsNextAction } from './settings-next-action';
import { ModulesHubQueryService } from './modules-hub-query.service';

export class ModulesHubReadService {
  constructor(
    private readonly readRepo: SettingsReadRepo,
    private readonly modulesQuery: ModulesHubQueryService,
  ) {}

  async getModulesHub(tenantId: string): Promise<ModulesHubDto> {
    const [state, cpHandoff] = await Promise.all([
      this.readRepo.getStateBundle(tenantId),
      this.readRepo.getCpHandoffByTenantId(tenantId),
    ]);

    if (!state) {
      throw new Error(`Settings foundation rows not found for tenant ${tenantId}`);
    }

    const modules = this.modulesQuery.build({
      personalStatus: state.sections.personal.status,
      cpHandoff,
    });

    return {
      title: 'Modules',
      description:
        'This hub is navigation-only in v1. Personal is the only live actionable module route. Future modules remain non-interactive placeholders when allowed by Control Plane.',
      cards: modules.cards,
      visibleModuleKeys: modules.visibleModuleKeys,
      nextAction: deriveSettingsNextAction({
        overallStatus: state.aggregate.overallStatus,
        accessStatus: state.sections.access.status,
        personalStatus: state.sections.personal.status,
        personalRequired: modules.personalEnabled,
      }),
    };
  }
}
