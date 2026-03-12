/**
 * frontend/src/shared/auth/bootstrap.server.ts
 *
 * WHY:
 * - Performs the authoritative SSR auth bootstrap for the current request.
 * - Reads `/auth/config` first, then `/auth/me` when the tenant is available.
 * - Converts backend truth into a route-state decision the root gate can trust.
 *
 * RULES:
 * - Server-only. Uses ssrFetch().
 * - `/auth/config` is always fetched first.
 * - `/auth/me` 401 means "no active session" — not a fatal bootstrap error.
 * - All other non-2xx responses are treated as real bootstrap failures.
 */

import { ssrFetch } from '@/shared/ssr-api-client';
import { ApiHttpError, readApiError } from './api-errors';
import type { ConfigResponse, MeResponse } from './contracts';
import { resolveAuthRouteState, type AuthRouteState } from './route-state';

export type AuthBootstrapSuccess = {
  ok: true;
  config: ConfigResponse;
  me: MeResponse | null;
  routeState: AuthRouteState;
};

export type AuthBootstrapFailure = {
  ok: false;
  config: null;
  me: null;
  error: ApiHttpError | Error;
};

export type AuthBootstrapResult = AuthBootstrapSuccess | AuthBootstrapFailure;

async function fetchJsonOrThrow<T>(path: string): Promise<T> {
  const response = await ssrFetch(path);

  if (!response.ok) {
    throw await readApiError(response);
  }

  return (await response.json()) as T;
}

async function fetchConfig(): Promise<ConfigResponse> {
  return fetchJsonOrThrow<ConfigResponse>('/auth/config');
}

async function fetchMe(): Promise<MeResponse | null> {
  const response = await ssrFetch('/auth/me');

  if (response.status === 401) {
    return null;
  }

  if (!response.ok) {
    throw await readApiError(response);
  }

  return (await response.json()) as MeResponse;
}

export async function loadAuthBootstrap(): Promise<AuthBootstrapResult> {
  try {
    const config = await fetchConfig();
    const me = config.tenant.isActive ? await fetchMe() : null;
    const routeState = resolveAuthRouteState({ config, me });

    return {
      ok: true,
      config,
      me,
      routeState,
    };
  } catch (error) {
    return {
      ok: false,
      config: null,
      me: null,
      error: error instanceof Error ? error : new Error('Unknown bootstrap error'),
    };
  }
}
