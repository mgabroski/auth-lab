import { AppError } from '../../../shared/http/errors';
import type { Tenant } from '../tenant.types';

/**
 * Tenant safety rules:
 * - Pure (no DB / no I/O)
 * - Throws AppError
 */

export function assertTenantKeyPresent(tenantKey: string | null): asserts tenantKey is string {
  if (!tenantKey) {
    throw AppError.tenantKeyMissing();
  }
}

export function assertTenantExists(
  tenant: Tenant | undefined,
  tenantKey: string,
): asserts tenant is Tenant {
  if (!tenant) {
    throw AppError.tenantNotFound({ tenantKey });
  }
}

export function assertTenantIsActive(tenant: Tenant): void {
  if (!tenant.isActive) {
    throw AppError.tenantInactive({
      tenantId: tenant.id,
      tenantKey: tenant.key,
    });
  }
}
