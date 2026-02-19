/**
 * backend/src/modules/tenants/use-cases/resolve-tenant.ts
 *
 * WHY:
 * - Centralize the canonical tenant resolution sequence in the tenants module.
 * - Prevent auth (and future modules) from deep-importing tenant queries/policies.
 * - Keeps the 4-step order from the legacy helper:
 *   assertKeyPresent → getTenantByKey → assertExists → assertActive
 *
 * RULES:
 * - Pure orchestration of existing policies + queries. No new logic.
 * - Receives a trx-bound DbExecutor (caller owns the transaction).
 * - Throws via existing policy functions (TenantErrors).
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { Tenant } from '../tenant.types';
import { getTenantByKey } from '../queries/tenant.queries';
import {
  assertTenantKeyPresent,
  assertTenantExists,
  assertTenantIsActive,
} from '../policies/tenant-safety.policy';

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
