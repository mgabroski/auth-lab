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
 *
 * STAGE 3:
 * - Marks bootstrap fetches with x-auth-bootstrap so backend metrics can count
 *   real SSR bootstrap failures.
 * - Emits structured frontend server logs for config/me bootstrap failures.
 */

import { ssrFetch } from '@/shared/ssr-api-client';
import { serverLogger } from '@/shared/server/logger';
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

const BOOTSTRAP_HEADERS = {
  'X-Auth-Bootstrap': '1',
} as const;

async function fetchConfig(): Promise<ConfigResponse> {
  try {
    const response = await ssrFetch('/auth/config', {
      headers: BOOTSTRAP_HEADERS,
    });

    if (!response.ok) {
      const error = await readApiError(response);

      serverLogger.error('auth.bootstrap.config_failed', {
        event: 'auth.bootstrap.config_failed',
        flow: 'ssr.bootstrap',
        target: 'config',
        status: response.status,
        code: error.code,
        backendRequestId: response.headers.get('x-request-id'),
        error: error.message,
      });

      throw error;
    }

    return (await response.json()) as ConfigResponse;
  } catch (error) {
    if (!(error instanceof ApiHttpError)) {
      serverLogger.error('auth.bootstrap.config_transport_failed', {
        event: 'auth.bootstrap.config_transport_failed',
        flow: 'ssr.bootstrap',
        target: 'config',
        error,
      });
    }

    throw error;
  }
}

async function fetchMe(): Promise<MeResponse | null> {
  try {
    const response = await ssrFetch('/auth/me', {
      headers: BOOTSTRAP_HEADERS,
    });

    if (response.status === 401) {
      return null;
    }

    if (!response.ok) {
      const error = await readApiError(response);

      serverLogger.error('auth.bootstrap.me_failed', {
        event: 'auth.bootstrap.me_failed',
        flow: 'ssr.bootstrap',
        target: 'me',
        status: response.status,
        code: error.code,
        backendRequestId: response.headers.get('x-request-id'),
        error: error.message,
      });

      throw error;
    }

    return (await response.json()) as MeResponse;
  } catch (error) {
    if (!(error instanceof ApiHttpError)) {
      serverLogger.error('auth.bootstrap.me_transport_failed', {
        event: 'auth.bootstrap.me_transport_failed',
        flow: 'ssr.bootstrap',
        target: 'me',
        error,
      });
    }

    throw error;
  }
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
    if (!(error instanceof ApiHttpError) && !(error instanceof Error)) {
      serverLogger.error('auth.bootstrap.unknown_failure', {
        event: 'auth.bootstrap.unknown_failure',
        flow: 'ssr.bootstrap',
        error,
      });
    }

    return {
      ok: false,
      config: null,
      me: null,
      error: error instanceof Error ? error : new Error('Unknown bootstrap error'),
    };
  }
}
