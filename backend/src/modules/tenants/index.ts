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
 */

export { resolveTenantForAuth } from './use-cases/resolve-tenant';
export type { Tenant } from './tenant.types';
