/**
 * frontend/src/shared/people-teams/browser-api.ts
 *
 * WHY:
 * - Centralizes browser-side People & Teams API calls through the same-origin
 *   `/api/*` proxy contract.
 * - Keeps client components thin and grounded in backend-owned DTOs.
 */

import { apiFetch } from '@/shared/api-client';
import { readApiError, type ApiHttpError } from '@/shared/auth/api-errors';
import type {
  AddPeopleTeamGroupMemberRequest,
  CreatePeopleTeamGroupRequest,
  PeopleTeamGroupMemberResponse,
  PeopleTeamGroupMembersResponse,
  PeopleTeamGroupResponse,
  PeopleTeamGroupsResponse,
  PeopleTeamPeopleResponse,
  UpdatePeopleTeamGroupRequest,
} from './contracts';

export type BrowserPeopleTeamsSuccess<T> = {
  ok: true;
  status: number;
  data: T;
};

export type BrowserPeopleTeamsFailure = {
  ok: false;
  status: number;
  error: ApiHttpError;
};

export type BrowserPeopleTeamsResult<T> = BrowserPeopleTeamsSuccess<T> | BrowserPeopleTeamsFailure;

async function requestJson<T>(
  path: string,
  init?: RequestInit,
): Promise<BrowserPeopleTeamsResult<T>> {
  const response = await apiFetch(path, init);

  if (!response.ok) {
    const error = await readApiError(response);
    return {
      ok: false,
      status: response.status,
      error,
    };
  }

  return {
    ok: true,
    status: response.status,
    data: (await response.json()) as T,
  };
}

export function fetchPeopleTeamGroupsBrowser(): Promise<
  BrowserPeopleTeamsResult<PeopleTeamGroupsResponse>
> {
  return requestJson<PeopleTeamGroupsResponse>('/people-teams/groups', {
    method: 'GET',
  });
}

export function fetchPeopleTeamPeopleBrowser(): Promise<
  BrowserPeopleTeamsResult<PeopleTeamPeopleResponse>
> {
  return requestJson<PeopleTeamPeopleResponse>('/people-teams/people', {
    method: 'GET',
  });
}

export function createPeopleTeamGroup(
  input: CreatePeopleTeamGroupRequest,
): Promise<BrowserPeopleTeamsResult<PeopleTeamGroupResponse>> {
  return requestJson<PeopleTeamGroupResponse>('/people-teams/groups', {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function updatePeopleTeamGroup(
  groupId: string,
  input: UpdatePeopleTeamGroupRequest,
): Promise<BrowserPeopleTeamsResult<PeopleTeamGroupResponse>> {
  return requestJson<PeopleTeamGroupResponse>(`/people-teams/groups/${groupId}`, {
    method: 'PUT',
    body: JSON.stringify(input),
  });
}

export function archivePeopleTeamGroup(
  groupId: string,
): Promise<BrowserPeopleTeamsResult<PeopleTeamGroupResponse>> {
  return requestJson<PeopleTeamGroupResponse>(`/people-teams/groups/${groupId}/archive`, {
    method: 'POST',
  });
}

export function fetchPeopleTeamGroupMembersBrowser(
  groupId: string,
): Promise<BrowserPeopleTeamsResult<PeopleTeamGroupMembersResponse>> {
  return requestJson<PeopleTeamGroupMembersResponse>(`/people-teams/groups/${groupId}/members`, {
    method: 'GET',
  });
}

export function addPeopleTeamGroupMember(
  groupId: string,
  input: AddPeopleTeamGroupMemberRequest,
): Promise<BrowserPeopleTeamsResult<PeopleTeamGroupMemberResponse>> {
  return requestJson<PeopleTeamGroupMemberResponse>(`/people-teams/groups/${groupId}/members`, {
    method: 'POST',
    body: JSON.stringify(input),
  });
}

export function removePeopleTeamGroupMember(
  groupId: string,
  membershipId: string,
): Promise<BrowserPeopleTeamsResult<PeopleTeamGroupMemberResponse>> {
  return requestJson<PeopleTeamGroupMemberResponse>(
    `/people-teams/groups/${groupId}/members/${membershipId}`,
    {
      method: 'DELETE',
    },
  );
}
