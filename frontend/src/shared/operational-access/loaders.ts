/**
 * frontend/src/shared/operational-access/loaders.ts
 *
 * WHY:
 * - Provides SSR loaders for the Operational Access admin shell.
 * - Keeps route pages from inventing fallback access truth when backend reads fail.
 */

import { ssrFetch } from '@/shared/ssr-api-client';
import { serverLogger } from '@/shared/server/logger';
import { ApiHttpError, readApiError } from '@/shared/auth/api-errors';
import type {
  OperationalAccessCatalogResponse,
  OperationalAccessFoundationResponse,
  OperationalAccessGroupsResponse,
  OperationalAccessPeopleResponse,
} from './contracts';

export type OperationalAccessLoadSuccess<T> = {
  ok: true;
  data: T;
};

export type OperationalAccessLoadFailure = {
  ok: false;
  error: ApiHttpError | Error;
};

export type OperationalAccessLoadResult<T> =
  | OperationalAccessLoadSuccess<T>
  | OperationalAccessLoadFailure;

async function fetchOperationalAccessJson<T>(path: string): Promise<T> {
  try {
    const response = await ssrFetch(path, {
      headers: { 'X-Operational-Access': '1' },
    });

    if (!response.ok) {
      const error = await readApiError(response);
      serverLogger.error('operational_access.load_failed', {
        event: 'operational_access.load_failed',
        flow: 'ssr.operational_access',
        path,
        status: response.status,
        code: error.code,
        backendRequestId: response.headers.get('x-request-id'),
        error: error.message,
      });
      throw error;
    }

    return (await response.json()) as T;
  } catch (error) {
    if (!(error instanceof ApiHttpError)) {
      serverLogger.error('operational_access.transport_failed', {
        event: 'operational_access.transport_failed',
        flow: 'ssr.operational_access',
        path,
        error,
      });
    }
    throw error;
  }
}

export async function loadOperationalAccessFoundation(): Promise<
  OperationalAccessLoadResult<OperationalAccessFoundationResponse>
> {
  try {
    const [catalog, groups, people] = await Promise.all([
      fetchOperationalAccessJson<OperationalAccessCatalogResponse>('/operational-access/catalog'),
      fetchOperationalAccessJson<OperationalAccessGroupsResponse>('/operational-access/groups'),
      fetchOperationalAccessJson<OperationalAccessPeopleResponse>('/operational-access/people'),
    ]);

    return {
      ok: true,
      data: {
        catalog: catalog.catalog,
        groups: groups.groups,
        people: people.people,
      },
    };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error : new Error('Unknown Operational Access load error'),
    };
  }
}
