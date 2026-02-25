/**
 * backend/src/modules/tenants/index.ts
 *
 * WHY:
 * - Define the public surface of the tenants module.
 * - Prevent cross-module coupling via deep imports into /queries or /policies.
 *
 * RULES:
 * - Only export stable, read-only contracts needed by other modules.
 * - Keep exports minimal; add more only when explicitly required.
 *
 * BRICK 12 UPDATE:
 * - Exported getTenantById for admin flows that resolve tenant from session.tenantId.
 */

export { resolveTenantForAuth } from './use-cases/resolve-tenant';
export { isEmailDomainAllowed, assertEmailDomainAllowed } from './policies/tenant-access.policy';
export { getTenantById } from './queries/tenant.queries';
export type { Tenant } from './tenant.types';
