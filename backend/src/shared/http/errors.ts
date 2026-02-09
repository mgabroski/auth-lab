/**
 * backend/src/shared/http/errors.ts
 *
 * WHY:
 * - Central error type used across controllers/services.
 * - Keeps API error responses consistent.
 */

export const APP_ERROR_CODES = [
  'TENANT_KEY_MISSING',
  'TENANT_NOT_FOUND',
  'TENANT_INACTIVE',

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

  static tenantKeyMissing(meta?: AppErrorMeta) {
    return new AppError({
      code: 'TENANT_KEY_MISSING',
      status: 400,
      message: 'Tenant key is missing from request host.',
      meta,
    });
  }

  static tenantNotFound(meta?: AppErrorMeta) {
    return new AppError({
      code: 'TENANT_NOT_FOUND',
      status: 404,
      message: 'Tenant not found',
      meta,
    });
  }

  static tenantInactive(meta?: AppErrorMeta) {
    return new AppError({
      code: 'TENANT_INACTIVE',
      status: 403,
      message: 'Tenant is inactive',
      meta,
    });
  }

  static unauthorized(meta?: AppErrorMeta) {
    return new AppError({
      code: 'UNAUTHORIZED',
      status: 401,
      message: 'Unauthorized',
      meta,
    });
  }

  static forbidden(meta?: AppErrorMeta) {
    return new AppError({
      code: 'FORBIDDEN',
      status: 403,
      message: 'Forbidden',
      meta,
    });
  }

  static notFound(meta?: AppErrorMeta) {
    return new AppError({
      code: 'NOT_FOUND',
      status: 404,
      message: 'Not found',
      meta,
    });
  }

  static validationError(message = 'Validation error', meta?: AppErrorMeta) {
    return new AppError({
      code: 'VALIDATION_ERROR',
      status: 400,
      message,
      meta,
    });
  }

  static rateLimited(meta?: AppErrorMeta) {
    return new AppError({
      code: 'RATE_LIMITED',
      status: 429,
      message: 'Rate limited',
      meta,
    });
  }

  static conflict(message = 'Conflict', meta?: AppErrorMeta) {
    return new AppError({
      code: 'CONFLICT',
      status: 409,
      message,
      meta,
    });
  }

  static internal(message = 'Internal error', meta?: AppErrorMeta) {
    return new AppError({
      code: 'INTERNAL',
      status: 500,
      message,
      meta,
    });
  }
}
