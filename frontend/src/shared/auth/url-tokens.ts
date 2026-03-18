/**
 * frontend/src/shared/auth/url-tokens.ts
 *
 * WHY:
 * - Upcoming auth pages need one small, reusable place to read token/query values
 *   from URLs without duplicating parsing logic.
 * - Supports both Next.js server-page `searchParams` objects and browser URLSearchParams.
 * - Keeps reset / verify / invite / returnTo parsing consistent with backend expectations.
 *
 * TRIMMING CONTRACT:
 * - All read functions trim whitespace and return null for blank values.
 * - This applies consistently across all input types (string, URL, URLSearchParams, object).
 * - A token or path that is only whitespace is treated as absent.
 */

export type SearchParamValue = string | string[] | undefined;
export type SearchParamsRecord = Record<string, SearchParamValue>;

type SearchParamsWithGet = {
  get(name: string): string | null;
};

export type SearchParamsInput =
  | URLSearchParams
  | URL
  | string
  | SearchParamsRecord
  | SearchParamsWithGet;

function trimOrNull(value: string | null | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}

function getFirstValue(value: SearchParamValue): string | null {
  if (typeof value === 'string') {
    return trimOrNull(value);
  }

  if (Array.isArray(value)) {
    for (const entry of value) {
      const result = trimOrNull(entry);
      if (result) return result;
    }
  }

  return null;
}

function fromString(input: string): URLSearchParams {
  const value = input.startsWith('?') ? input.slice(1) : input;
  return new URLSearchParams(value);
}

function hasGetMethod(value: unknown): value is SearchParamsWithGet {
  return typeof value === 'object' && value !== null && 'get' in value;
}

function readFromSearchParams(searchParams: SearchParamsInput, key: string): string | null {
  if (typeof searchParams === 'string') {
    return trimOrNull(fromString(searchParams).get(key));
  }

  if (searchParams instanceof URL) {
    return trimOrNull(searchParams.searchParams.get(key));
  }

  if (searchParams instanceof URLSearchParams || hasGetMethod(searchParams)) {
    return trimOrNull(searchParams.get(key));
  }

  return getFirstValue(searchParams[key]);
}

export function readQueryParam(searchParams: SearchParamsInput, key: string): string | null {
  return readFromSearchParams(searchParams, key);
}

export function readTokenQueryParam(searchParams: SearchParamsInput): string | null {
  return readQueryParam(searchParams, 'token');
}

export function getInviteToken(searchParams: SearchParamsInput): string | null {
  return readTokenQueryParam(searchParams);
}

export function getResetPasswordToken(searchParams: SearchParamsInput): string | null {
  return readTokenQueryParam(searchParams);
}

export function getVerificationToken(searchParams: SearchParamsInput): string | null {
  return readTokenQueryParam(searchParams);
}

export function isSafeReturnToPath(value: string | null | undefined): value is string {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//');
}

export function getReturnToPath(searchParams: SearchParamsInput): string | null {
  const returnTo = readQueryParam(searchParams, 'returnTo');
  return isSafeReturnToPath(returnTo) ? returnTo : null;
}

export function normalizeReturnToPath(value: string | null | undefined, fallback = '/'): string {
  return isSafeReturnToPath(value) ? value : fallback;
}
