/**
 * backend/src/modules/settings/services/modules-hub-query.service.ts
 *
 * WHY:
 * - Encodes the locked v1 Modules hub rule: there is no independent persisted
 *   Modules state row, and Personal is the only live actionable child.
 */

import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';
import type { SettingsSetupStatus } from '../settings.types';

export type ModulesHubReadModel = {
  personalEnabled: boolean;
  status: SettingsSetupStatus;
};

export class ModulesHubQueryService {
  build(params: {
    personalStatus: SettingsSetupStatus;
    cpHandoff?: CpSettingsHandoffSnapshot;
  }): ModulesHubReadModel {
    return {
      personalEnabled: params.cpHandoff?.allowances.modules.modules.personal ?? true,
      status: params.personalStatus,
    };
  }
}
