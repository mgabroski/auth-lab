/**
 * backend/test/helpers/tenant-host.ts
 *
 * WHY:
 * - Backend E2E tests frequently need to construct a tenant host header.
 * - Keeping this in one helper avoids tiny copy/paste drift across tests.
 */

export function hostForTenant(tenantKey: string, rootHost = 'hubins.com'): string {
  return `${tenantKey}.${rootHost}`;
}
