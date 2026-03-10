/**
 * src/modules/auth/helpers/get-auth-config.ts
 *
 * WHY:
 * - Owns all public read-side logic for GET /auth/config.
 * - Returns a frontend-safe tenant bootstrap payload without leaking internal policy.
 * - Preserves anti-enumeration parity between unknown and inactive workspaces.
 *
 * RULES:
 * - No session required.
 * - No audit events or rate limits.
 * - Never return allowedEmailDomains or memberMfaRequired.
 * - Unknown and inactive tenants must return the identical unavailable shape.
 */

import type { DbExecutor } from '../../../shared/db/db';
import { getTenantByKey } from '../../tenants/queries/tenant.queries';
import type { ConfigResponse } from '../auth.types';

const UNAVAILABLE: ConfigResponse = {
  tenant: {
    name: '',
    isActive: false,
    publicSignupEnabled: false,
    allowedSso: [],
  },
};

const PROVIDER_ORDER: ('google' | 'microsoft')[] = ['google', 'microsoft'];

export async function getAuthConfig(
  tenantKey: string | null,
  db: DbExecutor,
): Promise<ConfigResponse> {
  if (!tenantKey) {
    return UNAVAILABLE;
  }

  const tenant = await getTenantByKey(db, tenantKey);
  if (!tenant || tenant.isActive === false) {
    return UNAVAILABLE;
  }

  return {
    tenant: {
      name: tenant.name,
      isActive: tenant.isActive,
      publicSignupEnabled: tenant.publicSignupEnabled,
      allowedSso: PROVIDER_ORDER.filter((provider) => tenant.allowedSso.includes(provider)),
    },
  };
}
