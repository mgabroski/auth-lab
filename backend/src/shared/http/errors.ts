/**
 * backend/src/shared/http/errors.ts
 *
 * WHY:
 * - Central error primitive used across controllers/services.
 * - Keeps API error responses consistent.
 *
 * RULES:
 * - This file MUST stay small.
 * - Do NOT add module-specific error factories here.
 * - Each module owns its own semantic error factories (e.g. tenants/tenant.errors.ts).
 *
 * X6 — Custom message on rateLimited():
 * - Previously rateLimited() always returned the generic "Rate limited" string.
 * - The provisioning spec mandates exact copy for login lockout:
 *   "Too many failed attempts. Try again in 15 minutes."
 * - Fix: accept an optional second `message` param so call sites can supply
 *   the locked copy. The default fallback ("Rate limited") keeps all other
 *   rate-limited paths unchanged.
 */

export const APP_ERROR_CODES = [
  'UNAUTHORIZED',
  'FORBIDDEN',
  'NOT_FOUND',
  'VALIDATION_ERROR',
  'RATE_LIMITED',
  'CONFLICT',
  'INTERNAL',
] as const;

export type AppErrorCode = (typeof APP_ERROR_CODES)[number];
export type AppErrorMeta = Record<string, unknown>;

export class AppError extends Error {
  readonly code: AppErrorCode;
  readonly status: number;
  readonly meta?: AppErrorMeta;

  constructor(opts: { code: AppErrorCode; message: string; status: number; meta?: AppErrorMeta }) {
    super(opts.message);
    this.name = 'AppError';
    this.code = opts.code;
    this.status = opts.status;
    this.meta = opts.meta;
  }

  static unauthorized(message = 'Unauthorized', meta?: AppErrorMeta) {
    return new AppError({ code: 'UNAUTHORIZED', status: 401, message, meta });
  }

  static forbidden(message = 'Forbidden', meta?: AppErrorMeta) {
    return new AppError({ code: 'FORBIDDEN', status: 403, message, meta });
  }

  static notFound(message = 'Not found', meta?: AppErrorMeta) {
    return new AppError({ code: 'NOT_FOUND', status: 404, message, meta });
  }

  static validationError(message = 'Validation error', meta?: AppErrorMeta) {
    return new AppError({ code: 'VALIDATION_ERROR', status: 400, message, meta });
  }

  /**
   * X6: Accepts an optional `message` param so callers can supply locked copy
   * (e.g. LOGIN_LOCKOUT_MESSAGE from rate-limit.ts). Defaults to "Rate limited"
   * for all other rate-limited paths — no behavior change at existing call sites.
   */
  static rateLimited(meta?: AppErrorMeta, message?: string) {
    return new AppError({
      code: 'RATE_LIMITED',
      status: 429,
      message: message ?? 'Rate limited',
      meta,
    });
  }

  static conflict(message = 'Conflict', meta?: AppErrorMeta) {
    return new AppError({ code: 'CONFLICT', status: 409, message, meta });
  }

  static internal(message = 'Internal error', meta?: AppErrorMeta) {
    return new AppError({ code: 'INTERNAL', status: 500, message, meta });
  }
}
