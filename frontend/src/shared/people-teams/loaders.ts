/**
 * frontend/src/shared/people-teams/loaders.ts
 *
 * WHY:
 * - Provides SSR loaders for the People & Teams tenant-admin page.
 * - Keeps route pages thin while preserving backend-authoritative tenant and
 *   admin access checks.
 */

import { readApiError, type ApiHttpError } from '@/shared/auth/api-errors';
import { serverLogger } from '@/shared/server/logger';
import { ssrFetch } from '@/shared/ssr-api-client';
import type {
  PeopleTeamGroupsResponse,
  PeopleTeamPeopleResponse,
  PeopleTeamsFoundationResponse,
} from './contracts';

export type PeopleTeamsLoadSuccess<T> = {
  ok: true;
  data: T;
};

export type PeopleTeamsLoadFailure = {
  ok: false;
  error: ApiHttpError | Error;
};

export type PeopleTeamsLoadResult<T> = PeopleTeamsLoadSuccess<T> | PeopleTeamsLoadFailure;

const PEOPLE_TEAMS_HEADERS = {
  'X-People-Teams': '1',
} as const;

async function fetchPeopleTeamsJson<T>(path: '/people-teams/groups' | '/people-teams/people') {
  const response = await ssrFetch(path, {
    headers: PEOPLE_TEAMS_HEADERS,
  });

  if (!response.ok) {
    const error = await readApiError(response);

    serverLogger.error('people_teams.load_failed', {
      event: 'people_teams.load_failed',
      flow: 'ssr.people_teams',
      path,
      status: response.status,
      code: error.code,
      backendRequestId: response.headers.get('x-request-id'),
      error: error.message,
    });

    throw error;
  }

  return (await response.json()) as T;
}

export async function loadPeopleTeamsFoundation(): Promise<
  PeopleTeamsLoadResult<PeopleTeamsFoundationResponse>
> {
  try {
    const [groupsResponse, peopleResponse] = await Promise.all([
      fetchPeopleTeamsJson<PeopleTeamGroupsResponse>('/people-teams/groups'),
      fetchPeopleTeamsJson<PeopleTeamPeopleResponse>('/people-teams/people'),
    ]);

    return {
      ok: true,
      data: {
        groups: groupsResponse.groups,
        people: peopleResponse.people,
      },
    };
  } catch (error) {
    if (!(error instanceof Error)) {
      return {
        ok: false,
        error: new Error('Unknown People & Teams load error'),
      };
    }

    return {
      ok: false,
      error,
    };
  }
}
