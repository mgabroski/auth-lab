/**
 * frontend/src/shared/auth/api-errors.ts
 *
 * WHY:
 * - Normalizes backend error responses for SSR bootstrap and browser auth flows.
 * - Lets the frontend distinguish expected auth states from infrastructure failures.
 * - Provides one shared way to extract a user-facing message for banners/forms.
 *
 * RULES:
 * - Grounded in backend shared error-handler shape:
 *   { error: { code: string; message: string } }
 * - Never assume every non-2xx response contains JSON.
 * - Do not invent frontend-only error envelopes.
 */

import type { BackendErrorResponse } from './contracts';

export class ApiHttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly body: unknown;

  constructor(opts: { status: number; code: string; message: string; body?: unknown }) {
    super(opts.message);
    this.name = 'ApiHttpError';
    this.status = opts.status;
    this.code = opts.code;
    this.body = opts.body;
  }
}

export function isApiHttpError(value: unknown): value is ApiHttpError {
  return value instanceof ApiHttpError;
}

export function isBackendErrorResponse(value: unknown): value is BackendErrorResponse {
  if (!value || typeof value !== 'object') return false;

  const candidate = value as Partial<BackendErrorResponse>;
  if (!candidate.error || typeof candidate.error !== 'object') return false;

  return typeof candidate.error.code === 'string' && typeof candidate.error.message === 'string';
}

export async function readApiError(response: Response): Promise<ApiHttpError> {
  let body: unknown = null;

  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (isBackendErrorResponse(body)) {
    return new ApiHttpError({
      status: response.status,
      code: body.error.code,
      message: body.error.message,
      body,
    });
  }

  return new ApiHttpError({
    status: response.status,
    code: `HTTP_${response.status}`,
    message: response.statusText || `HTTP ${response.status}`,
    body,
  });
}

export function getApiErrorMessage(
  error: unknown,
  fallbackMessage = 'Something went wrong. Please try again.',
): string {
  if (typeof error === 'string' && error.trim().length) {
    return error;
  }

  if (isApiHttpError(error) && error.message.trim().length) {
    return error.message;
  }

  if (error instanceof Error && error.message.trim().length) {
    return error.message;
  }

  return fallbackMessage;
}
