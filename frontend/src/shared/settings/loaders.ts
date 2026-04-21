/**
 * frontend/src/shared/settings/loaders.ts
 *
 * WHY:
 * - Provides the SSR loaders for the current Settings-native frontend consumers.
 * - Keeps Settings fetch/log/error handling out of route pages.
 * - Makes the auth-vs-settings boundary explicit: auth bootstrap still owns
 *   session and route gating, while Settings loaders own setup progress truth.
 *
 * RULES:
 * - Server-only. Uses ssrFetch().
 * - No frontend-owned completion logic.
 * - Do not fall back to auth scaffold truth when these reads fail.
 */

import { ssrFetch } from '@/shared/ssr-api-client';
import { serverLogger } from '@/shared/server/logger';
import { ApiHttpError, readApiError } from '@/shared/auth/api-errors';
import type {
  AccessSettingsResponse,
  AccountSettingsResponse,
  SettingsBootstrapResponse,
  SettingsOverviewResponse,
} from './contracts';

export type SettingsLoadSuccess<T> = {
  ok: true;
  data: T;
};

export type SettingsLoadFailure = {
  ok: false;
  error: ApiHttpError | Error;
};

export type SettingsLoadResult<T> = SettingsLoadSuccess<T> | SettingsLoadFailure;

const SETTINGS_BOOTSTRAP_HEADERS = {
  'X-Settings-Bootstrap': '1',
} as const;

const SETTINGS_OVERVIEW_HEADERS = {
  'X-Settings-Overview': '1',
} as const;

const SETTINGS_ACCESS_HEADERS = {
  'X-Settings-Access': '1',
} as const;

const SETTINGS_ACCOUNT_HEADERS = {
  'X-Settings-Account': '1',
} as const;

async function fetchSettingsJson<T>(params: {
  path: '/settings/bootstrap' | '/settings/overview' | '/settings/access' | '/settings/account';
  target: 'bootstrap' | 'overview' | 'access' | 'account';
  headers: Record<string, string>;
}): Promise<T> {
  try {
    const response = await ssrFetch(params.path, {
      headers: params.headers,
    });

    if (!response.ok) {
      const error = await readApiError(response);

      serverLogger.error(`settings.${params.target}.load_failed`, {
        event: `settings.${params.target}.load_failed`,
        flow: 'ssr.settings',
        target: params.target,
        path: params.path,
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
      serverLogger.error(`settings.${params.target}.transport_failed`, {
        event: `settings.${params.target}.transport_failed`,
        flow: 'ssr.settings',
        target: params.target,
        path: params.path,
        error,
      });
    }

    throw error;
  }
}

export async function loadSettingsBootstrap(): Promise<
  SettingsLoadResult<SettingsBootstrapResponse>
> {
  try {
    const data = await fetchSettingsJson<SettingsBootstrapResponse>({
      path: '/settings/bootstrap',
      target: 'bootstrap',
      headers: SETTINGS_BOOTSTRAP_HEADERS,
    });

    return {
      ok: true,
      data,
    };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error : new Error('Unknown settings bootstrap error'),
    };
  }
}

export async function loadSettingsOverview(): Promise<
  SettingsLoadResult<SettingsOverviewResponse>
> {
  try {
    const data = await fetchSettingsJson<SettingsOverviewResponse>({
      path: '/settings/overview',
      target: 'overview',
      headers: SETTINGS_OVERVIEW_HEADERS,
    });

    return {
      ok: true,
      data,
    };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error : new Error('Unknown settings overview error'),
    };
  }
}

export async function loadAccessSettings(): Promise<SettingsLoadResult<AccessSettingsResponse>> {
  try {
    const data = await fetchSettingsJson<AccessSettingsResponse>({
      path: '/settings/access',
      target: 'access',
      headers: SETTINGS_ACCESS_HEADERS,
    });

    return {
      ok: true,
      data,
    };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error : new Error('Unknown settings access error'),
    };
  }
}

export async function loadAccountSettings(): Promise<SettingsLoadResult<AccountSettingsResponse>> {
  try {
    const data = await fetchSettingsJson<AccountSettingsResponse>({
      path: '/settings/account',
      target: 'account',
      headers: SETTINGS_ACCOUNT_HEADERS,
    });

    return {
      ok: true,
      data,
    };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error : new Error('Unknown settings account error'),
    };
  }
}
