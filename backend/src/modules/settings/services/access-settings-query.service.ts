/**
 * backend/src/modules/settings/services/access-settings-query.service.ts
 *
 * WHY:
 * - Composes the read-model inputs for the Access section from either real CP
 *   allowance truth or the current tenant-runtime bridge when no CP-produced
 *   tenant exists yet.
 * - Keeps access-envelope read logic out of the bootstrap and overview
 *   composition services.
 */

import type { Tenant } from '../../tenants/tenant.types';
import type { CpSettingsHandoffSnapshot } from '../../control-plane/accounts/handoff/cp-settings-handoff.types';

export type AccessSettingsReadModel = {
  loginMethods: {
    password: boolean;
    google: boolean;
    microsoft: boolean;
  };
  mfaPolicy: {
    adminRequired: boolean;
    memberRequired: boolean;
  };
  signupPolicy: {
    publicSignup: boolean;
    adminInvitationsAllowed: boolean;
    allowedDomains: string[];
  };
};

export class AccessSettingsQueryService {
  build(params: {
    tenant: Tenant;
    cpHandoff?: CpSettingsHandoffSnapshot;
  }): AccessSettingsReadModel {
    if (params.cpHandoff) {
      return params.cpHandoff.allowances.access;
    }

    return {
      loginMethods: {
        password: true,
        google: params.tenant.allowedSso.includes('google'),
        microsoft: params.tenant.allowedSso.includes('microsoft'),
      },
      mfaPolicy: {
        adminRequired: true,
        memberRequired: params.tenant.memberMfaRequired,
      },
      signupPolicy: {
        publicSignup: params.tenant.publicSignupEnabled,
        adminInvitationsAllowed: true,
        allowedDomains: [...params.tenant.allowedEmailDomains],
      },
    };
  }
}
