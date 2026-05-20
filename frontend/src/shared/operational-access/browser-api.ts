/**
 * frontend/src/shared/operational-access/browser-api.ts
 *
 * WHY:
 * - Centralizes browser-side Operational Access admin writes and the first
 *   Personal Cards module read calls.
 * - Runtime read calls return backend-resolved, already-masked DTOs; the
 *   frontend must not compute effective access.
 */

import { apiFetch } from '@/shared/api-client';
import { readApiError, type ApiHttpError } from '@/shared/auth/api-errors';
import type {
  OperationalAccessAdvancedCoverageResponse,
  OperationalAccessGroupConfigurationResponse,
  PersonalCardDetailResponse,
  PersonalCardsListResponse,
  SaveOperationalAccessGroupGrantsRequest,
  SaveOperationalAccessOversightRequest,
  SaveOperationalAccessResponsibleForRequest,
  SaveOperationalAccessSpecialAccessRequest,
  SaveOperationalAccessTemporaryCoverageRequest,
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

export function saveOperationalAccessOversight(
  input: SaveOperationalAccessOversightRequest,
): Promise<BrowserOperationalAccessResult<OperationalAccessAdvancedCoverageResponse>> {
  return requestJson<OperationalAccessAdvancedCoverageResponse>(
    '/operational-access/advanced-coverage/oversight',
    {
      method: 'PUT',
      body: JSON.stringify(input),
    },
  );
}

export function saveOperationalAccessTemporaryCoverage(
  input: SaveOperationalAccessTemporaryCoverageRequest,
): Promise<BrowserOperationalAccessResult<OperationalAccessAdvancedCoverageResponse>> {
  return requestJson<OperationalAccessAdvancedCoverageResponse>(
    '/operational-access/advanced-coverage/temporary-coverage',
    {
      method: 'PUT',
      body: JSON.stringify(input),
    },
  );
}

export function saveOperationalAccessSpecialAccess(
  input: SaveOperationalAccessSpecialAccessRequest,
): Promise<BrowserOperationalAccessResult<OperationalAccessAdvancedCoverageResponse>> {
  return requestJson<OperationalAccessAdvancedCoverageResponse>(
    '/operational-access/advanced-coverage/special-access',
    {
      method: 'PUT',
      body: JSON.stringify(input),
    },
  );
}

export function listPersonalCards(): Promise<
  BrowserOperationalAccessResult<PersonalCardsListResponse>
> {
  return requestJson<PersonalCardsListResponse>('/personal/cards');
}

export function getPersonalCard(
  membershipId: string,
): Promise<BrowserOperationalAccessResult<PersonalCardDetailResponse>> {
  return requestJson<PersonalCardDetailResponse>(`/personal/cards/${membershipId}`);
}
