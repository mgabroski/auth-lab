/**
 * frontend/src/shared/settings/browser-api.ts
 *
 * WHY:
 * - Centralizes browser-side Settings reads and writes around the locked
 *   same-origin `/api/*` rule.
 * - Gives the live Settings write surfaces thin browser helpers instead of
 *   hand-written fetch logic.
 */

import { apiFetch } from '@/shared/api-client';
import { readApiError, type ApiHttpError } from '@/shared/auth/api-errors';
import type {
  PersonalSettingsResponse,
  SavePersonalSettingsRequest,
  SettingsMutationResultResponse,
} from './contracts';

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

export function saveAccountBranding(input: {
  expectedVersion: number;
  expectedCpRevision: number;
  values: {
    logoUrl: string | null;
    menuColor: string | null;
    fontColor: string | null;
    welcomeMessage: string | null;
  };
}): Promise<BrowserSettingsResult<SettingsMutationResultResponse>> {
  return requestJson<SettingsMutationResultResponse>('/settings/account/branding', {
    method: 'PUT',
    body: JSON.stringify(input),
  });
}

export function saveAccountOrgStructure(input: {
  expectedVersion: number;
  expectedCpRevision: number;
  values: {
    employers: string[];
    locations: string[];
  };
}): Promise<BrowserSettingsResult<SettingsMutationResultResponse>> {
  return requestJson<SettingsMutationResultResponse>('/settings/account/org-structure', {
    method: 'PUT',
    body: JSON.stringify(input),
  });
}

export function saveAccountCalendar(input: {
  expectedVersion: number;
  expectedCpRevision: number;
  values: {
    observedDates: string[];
  };
}): Promise<BrowserSettingsResult<SettingsMutationResultResponse>> {
  return requestJson<SettingsMutationResultResponse>('/settings/account/calendar', {
    method: 'PUT',
    body: JSON.stringify(input),
  });
}

export function fetchPersonalSettingsBrowser(): Promise<
  BrowserSettingsResult<PersonalSettingsResponse>
> {
  return requestJson<PersonalSettingsResponse>('/settings/modules/personal', {
    method: 'GET',
  });
}

export function savePersonalSettings(
  input: SavePersonalSettingsRequest,
): Promise<BrowserSettingsResult<SettingsMutationResultResponse>> {
  return requestJson<SettingsMutationResultResponse>('/settings/modules/personal', {
    method: 'PUT',
    body: JSON.stringify(input),
  });
}
