import type { DbExecutor } from '../../shared/db/db';
import type { RequestContext } from '../../shared/http/request-context';
import type { Tenant } from './tenant.types';
import { getTenantByKey } from './queries/tenant.queries';
import {
  assertTenantExists,
  assertTenantIsActive,
  assertTenantKeyPresent,
} from './policies/tenant-safety.policy';

/**
 * TenantModule = single reusable entrypoint for tenant resolution + safety.
 * Other modules call this instead of duplicating tenant logic.
 */

export type TenantModule = {
  resolveTenant: (ctx: RequestContext) => Promise<Tenant | undefined>;
  requireTenant: (ctx: RequestContext) => Promise<Tenant>;
};

export function createTenantModule(deps: { db: DbExecutor }): TenantModule {
  const { db } = deps;

  async function resolveTenant(ctx: RequestContext): Promise<Tenant | undefined> {
    // best-effort; doesn't throw
    if (!ctx.tenantKey) return undefined;
    return getTenantByKey(db, ctx.tenantKey);
  }

  async function requireTenant(ctx: RequestContext): Promise<Tenant> {
    // strict; throws if tenantKey missing
    assertTenantKeyPresent(ctx.tenantKey);

    const tenant = await getTenantByKey(db, ctx.tenantKey);
    assertTenantExists(tenant, ctx.tenantKey);
    assertTenantIsActive(tenant);

    return tenant;
  }

  return { resolveTenant, requireTenant };
}
