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

  static unauthorized(meta?: AppErrorMeta) {
    return new AppError({ code: 'UNAUTHORIZED', status: 401, message: 'Unauthorized', meta });
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

  static rateLimited(meta?: AppErrorMeta) {
    return new AppError({ code: 'RATE_LIMITED', status: 429, message: 'Rate limited', meta });
  }

  static conflict(message = 'Conflict', meta?: AppErrorMeta) {
    return new AppError({ code: 'CONFLICT', status: 409, message, meta });
  }

  static internal(message = 'Internal error', meta?: AppErrorMeta) {
    return new AppError({ code: 'INTERNAL', status: 500, message, meta });
  }
}
