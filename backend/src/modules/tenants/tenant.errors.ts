/**
 * backend/src/modules/tenants/tenant.errors.ts
 *
 * WHY:
 * - Tenants module owns its domain semantics.
 * - Keeps shared/http/errors.ts small and stable.
 *
 * RULES:
 * - Use AppError as the transport primitive.
 * - Put tenant-specific meaning here: messages + safe meta.
 */

import { AppError, type AppErrorMeta } from '../../shared/http/errors';

export const TenantErrors = {
  tenantKeyMissing(meta?: AppErrorMeta) {
    return AppError.validationError('Tenant key is missing from request host.', meta);
  },

  tenantNotFound(meta?: AppErrorMeta) {
    return AppError.notFound('Tenant not found', meta);
  },

  tenantInactive(meta?: AppErrorMeta) {
    return AppError.forbidden('Tenant is inactive', meta);
  },

  emailDomainNotAllowed(meta?: AppErrorMeta): AppError {
    return AppError.validationError(
      'Your email domain is not permitted. Contact your admin.',
      meta,
    );
  },
} as const;
