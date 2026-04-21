/**
 * frontend/src/shared/settings/browser-api.ts
 *
 * WHY:
 * - Centralizes browser-side Settings writes around the locked same-origin `/api/*` rule.
 * - Gives the Access acknowledge CTA one thin browser helper instead of hand-written fetch logic.
 */

import { apiFetch } from '@/shared/api-client';
import { readApiError, type ApiHttpError } from '@/shared/auth/api-errors';
import type { SettingsMutationResultResponse } from './contracts';

export type BrowserSettingsSuccess<T> = {
  ok: true;
  status: number;
  data: T;
};

export type BrowserSettingsFailure = {
  ok: false;
  status: number;
  error: ApiHttpError;
};

export type BrowserSettingsResult<T> = BrowserSettingsSuccess<T> | BrowserSettingsFailure;

async function requestJson<T>(path: string, init?: RequestInit): Promise<BrowserSettingsResult<T>> {
  const response = await apiFetch(path, init);

  if (!response.ok) {
    const error = await readApiError(response);
    return {
      ok: false,
      status: response.status,
      error,
    };
  }

  const data = (await response.json()) as T;

  return {
    ok: true,
    status: response.status,
    data,
  };
}

export function acknowledgeAccessSettings(input: {
  expectedVersion: number;
  expectedCpRevision: number;
}): Promise<BrowserSettingsResult<SettingsMutationResultResponse>> {
  return requestJson<SettingsMutationResultResponse>('/settings/access/acknowledge', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}
