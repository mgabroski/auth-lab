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
 *
 * X5 — Unified workspace unavailable response:
 * - Previously: tenantNotFound → 404, tenantInactive → 403, tenantKeyMissing → 400.
 *   Three different codes + messages form an enumeration oracle (attacker can
 *   distinguish non-existent from inactive from missing-key tenants).
 * - Fix: all three conditions produce byte-identical 404 + "This workspace is not
 *   available." The internal reason is stored in meta only — never sent to the client.
 * - workspaceUnavailable() is the canonical factory; the three named aliases keep
 *   call sites readable without exposing information to callers.
 */

import { AppError, type AppErrorMeta } from '../../shared/http/errors';

export const TenantErrors = {
  /**
   * Single external surface for all "workspace not usable" conditions.
   * "not_found", "inactive", "missing_key" are internal meta only.
   * The client always sees the same 404 + message — no enumeration oracle.
   */
  workspaceUnavailable(meta?: AppErrorMeta) {
    return AppError.notFound('This workspace is not available.', meta);
  },

  /**
   * Convenience alias — tenant row does not exist.
   * Previously returned 404 with a different message; now unified.
   */
  tenantNotFound(meta?: AppErrorMeta) {
    return TenantErrors.workspaceUnavailable({ ...meta, reason: 'not_found' });
  },

  /**
   * Convenience alias — tenant exists but isActive === false.
   * Previously returned 403 Forbidden; now unified to 404.
   */
  tenantInactive(meta?: AppErrorMeta) {
    return TenantErrors.workspaceUnavailable({ ...meta, reason: 'inactive' });
  },

  /**
   * Convenience alias — no tenantKey could be extracted from the request host.
   * Previously returned 400 validationError; now unified to 404.
   */
  tenantKeyMissing(meta?: AppErrorMeta) {
    return TenantErrors.workspaceUnavailable({ ...meta, reason: 'missing_key' });
  },

  emailDomainNotAllowed(meta?: AppErrorMeta): AppError {
    return AppError.validationError(
      'Your email domain is not permitted. Contact your admin.',
      meta,
    );
  },
} as const;
