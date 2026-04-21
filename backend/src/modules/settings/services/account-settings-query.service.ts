/**
 * backend/src/modules/settings/services/account-settings-query.service.ts
 *
 * WHY:
 * - Composes the current Account Settings allowance read model for overview and
 *   future section reads.
 * - Uses CP allowance truth when present and a conservative bridge default when
 *   the tenant was not provisioned through the Control Plane.
 */

import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';

export type AccountSettingsReadModel = {
  branding: {
    logo: boolean;
    menuColor: boolean;
    fontColor: boolean;
    welcomeMessage: boolean;
  };
  organizationStructure: {
    employers: boolean;
    locations: boolean;
  };
  companyCalendar: {
    allowed: boolean;
  };
};

export class AccountSettingsQueryService {
  build(params: { cpHandoff?: CpSettingsHandoffSnapshot }): AccountSettingsReadModel {
    if (params.cpHandoff) {
      return params.cpHandoff.allowances.account;
    }

    return {
      branding: {
        logo: true,
        menuColor: true,
        fontColor: true,
        welcomeMessage: true,
      },
      organizationStructure: {
        employers: true,
        locations: true,
      },
      companyCalendar: {
        allowed: true,
      },
    };
  }
}
