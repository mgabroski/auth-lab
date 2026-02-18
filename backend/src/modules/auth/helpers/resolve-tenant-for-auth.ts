/**
 * src/modules/auth/helpers/resolve-tenant-for-auth.ts
 *
 * WHY:
 * - The 4-step sequence (assertKeyPresent → getTenantByKey → assertExists → assertActive)
 *   is identical in register() and login(), and will repeat in SSO (Brick 10) and
 *   public signup (Brick 11).
 * - A single helper ensures the order of assertions never drifts between flows.
 *
 * RULES:
 * - Pure orchestration of existing policies + queries. No new logic.
 * - Receives a trx-bound DbExecutor (caller owns the transaction).
 * - Throws via existing policy functions (TenantErrors).
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { Tenant } from '../../tenants/tenant.types';
import { getTenantByKey } from '../../tenants/queries/tenant.queries';
import {
  assertTenantKeyPresent,
  assertTenantExists,
  assertTenantIsActive,
} from '../../tenants/policies/tenant-safety.policy';

export async function resolveTenantForAuth(
  trx: DbExecutor,
  tenantKey: string | null,
): Promise<Tenant> {
  assertTenantKeyPresent(tenantKey);
  const tenant = await getTenantByKey(trx, tenantKey);
  assertTenantExists(tenant, tenantKey);
  assertTenantIsActive(tenant);
  return tenant;
}
