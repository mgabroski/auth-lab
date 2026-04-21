import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiHttpError } from '../../../../src/shared/auth/api-errors';
import type {
  SettingsBootstrapResponse,
  SettingsOverviewResponse,
} from '../../../../src/shared/settings/contracts';

const { ssrFetchMock, serverLoggerErrorMock, serverLoggerInfoMock, serverLoggerWarnMock } =
  vi.hoisted(() => ({
    ssrFetchMock: vi.fn(),
    serverLoggerErrorMock: vi.fn(),
    serverLoggerInfoMock: vi.fn(),
    serverLoggerWarnMock: vi.fn(),
  }));

vi.mock('@/shared/ssr-api-client', () => ({
  ssrFetch: ssrFetchMock,
}));

vi.mock('@/shared/server/logger', () => ({
  serverLogger: {
    error: serverLoggerErrorMock,
    info: serverLoggerInfoMock,
    warn: serverLoggerWarnMock,
  },
}));

import {
  loadSettingsBootstrap,
  loadSettingsOverview,
} from '../../../../src/shared/settings/loaders';

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: init?.status ?? 200,
    statusText: init?.statusText,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
}

function makeBootstrap(
  overrides: Partial<SettingsBootstrapResponse> = {},
): SettingsBootstrapResponse {
  return {
    overallStatus: 'IN_PROGRESS',
    showSetupBanner: true,
    nextAction: {
      key: 'access',
      label: 'Review Access & Security',
      href: '/admin/settings/access',
    },
    ...overrides,
  };
}

function makeOverview(overrides: Partial<SettingsOverviewResponse> = {}): SettingsOverviewResponse {
  return {
    overallStatus: 'IN_PROGRESS',
    nextAction: {
      key: 'access',
      label: 'Review Access & Security',
      href: '/admin/settings/access',
    },
    cards: [
      {
        key: 'access',
        title: 'Access & Security',
        description: 'Review the access envelope.',
        href: '/admin/settings/access',
        classification: 'REQUIRED_GATING',
        status: 'IN_PROGRESS',
        warnings: [],
        isRequired: true,
      },
    ],
    ...overrides,
  };
}

afterEach(() => {
  ssrFetchMock.mockReset();
  serverLoggerErrorMock.mockReset();
  serverLoggerInfoMock.mockReset();
  serverLoggerWarnMock.mockReset();
});

describe('settings loaders', () => {
  it('loadSettingsBootstrap calls the Settings-native bootstrap endpoint with SSR headers', async () => {
    ssrFetchMock.mockResolvedValueOnce(jsonResponse(makeBootstrap()));

    const result = await loadSettingsBootstrap();

    expect(ssrFetchMock).toHaveBeenCalledWith('/settings/bootstrap', {
      headers: {
        'X-Settings-Bootstrap': '1',
      },
    });
    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected settings bootstrap success');
    }

    expect(result.data.showSetupBanner).toBe(true);
    expect(result.data.nextAction?.href).toBe('/admin/settings/access');
  });

  it('loadSettingsOverview returns a failure result and logs when the endpoint fails', async () => {
    ssrFetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          error: {
            code: 'HTTP_503',
            message: 'Settings overview unavailable',
          },
        },
        { status: 503, statusText: 'Service Unavailable' },
      ),
    );

    const result = await loadSettingsOverview();

    expect(result.ok).toBe(false);

    if (result.ok) {
      throw new Error('Expected settings overview failure');
    }

    expect(result.error).toBeInstanceOf(ApiHttpError);
    expect(result.error.message).toBe('Settings overview unavailable');
    expect(serverLoggerErrorMock).toHaveBeenCalledWith(
      'settings.overview.load_failed',
      expect.objectContaining({
        event: 'settings.overview.load_failed',
        flow: 'ssr.settings',
        target: 'overview',
        status: 503,
        code: 'HTTP_503',
        error: 'Settings overview unavailable',
      }),
    );
  });

  it('loadSettingsOverview returns the overview payload when the backend succeeds', async () => {
    ssrFetchMock.mockResolvedValueOnce(jsonResponse(makeOverview()));

    const result = await loadSettingsOverview();

    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected settings overview success');
    }

    expect(result.data.cards).toHaveLength(1);
    expect(result.data.cards[0]?.key).toBe('access');
  });
});
