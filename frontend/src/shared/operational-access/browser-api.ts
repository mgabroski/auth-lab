/**
 * frontend/src/shared/operational-access/browser-api.ts
 *
 * WHY:
 * - Centralizes browser-side Operational Access configuration API calls.
 * - These calls save configuration only; they do not resolve or grant runtime visibility.
 */

import { apiFetch } from '@/shared/api-client';
import { readApiError, type ApiHttpError } from '@/shared/auth/api-errors';
import type {
  OperationalAccessGroupConfigurationResponse,
  SaveOperationalAccessGroupGrantsRequest,
  SaveOperationalAccessResponsibleForRequest,
} from './contracts';

export type BrowserOperationalAccessSuccess<T> = {
  ok: true;
  status: number;
  data: T;
};

export type BrowserOperationalAccessFailure = {
  ok: false;
  status: number;
  error: ApiHttpError;
};

export type BrowserOperationalAccessResult<T> =
  | BrowserOperationalAccessSuccess<T>
  | BrowserOperationalAccessFailure;

async function requestJson<T>(
  path: string,
  init?: RequestInit,
): Promise<BrowserOperationalAccessResult<T>> {
  const response = await apiFetch(path, init);

  if (!response.ok) {
    const error = await readApiError(response);
    return { ok: false, status: response.status, error };
  }

  return {
    ok: true,
    status: response.status,
    data: (await response.json()) as T,
  };
}

export function saveOperationalAccessGroupGrants(
  groupId: string,
  input: SaveOperationalAccessGroupGrantsRequest,
): Promise<BrowserOperationalAccessResult<OperationalAccessGroupConfigurationResponse>> {
  return requestJson<OperationalAccessGroupConfigurationResponse>(
    `/operational-access/groups/${groupId}/grants`,
    {
      method: 'PUT',
      body: JSON.stringify(input),
    },
  );
}

export function saveOperationalAccessResponsibleFor(
  groupId: string,
  input: SaveOperationalAccessResponsibleForRequest,
): Promise<BrowserOperationalAccessResult<OperationalAccessGroupConfigurationResponse>> {
  return requestJson<OperationalAccessGroupConfigurationResponse>(
    `/operational-access/groups/${groupId}/responsible-for`,
    {
      method: 'PUT',
      body: JSON.stringify(input),
    },
  );
}
