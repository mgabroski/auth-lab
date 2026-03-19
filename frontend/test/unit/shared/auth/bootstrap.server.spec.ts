import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiHttpError } from '../../../../src/shared/auth/api-errors';
import type { ConfigResponse, MeResponse } from '../../../../src/shared/auth/contracts';

const { ssrFetchMock } = vi.hoisted(() => ({
  ssrFetchMock: vi.fn(),
}));

vi.mock('@/shared/ssr-api-client', () => ({
  ssrFetch: ssrFetchMock,
}));

import { loadAuthBootstrap } from '../../../../src/shared/auth/bootstrap.server';

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

function makeConfig(overrides: Partial<ConfigResponse['tenant']> = {}): ConfigResponse {
  return {
    tenant: {
      name: 'Acme',
      isActive: true,
      publicSignupEnabled: true,
      // signupAllowed is now a required field (publicSignupEnabled && !adminInviteRequired).
      // Default to true in tests — override explicitly when testing the blocked-signup case.
      signupAllowed: true,
      allowedSso: ['google'],
      // Phase 9: setupCompleted is a required field. Default to true in tests.
      setupCompleted: true,
      ...overrides,
    },
  };
}

function makeMe(overrides: Partial<MeResponse> = {}): MeResponse {
  return {
    user: {
      id: 'user-1',
      email: 'user@example.com',
      name: 'Test User',
    },
    membership: {
      id: 'membership-1',
      role: 'MEMBER',
    },
    tenant: {
      id: 'tenant-1',
      key: 'acme',
      name: 'Acme',
    },
    session: {
      mfaVerified: true,
      emailVerified: true,
    },
    nextAction: 'NONE',
    ...overrides,
  };
}

afterEach(() => {
  ssrFetchMock.mockReset();
});

describe('loadAuthBootstrap', () => {
  it('loads /auth/config first, then /auth/me for an active tenant, and returns the resolved route state', async () => {
    ssrFetchMock.mockImplementation((path: string) => {
      if (path === '/auth/config') {
        return jsonResponse(makeConfig());
      }

      if (path === '/auth/me') {
        return jsonResponse(makeMe());
      }

      throw new Error(`Unexpected path: ${path}`);
    });

    const result = await loadAuthBootstrap();

    expect(ssrFetchMock).toHaveBeenNthCalledWith(1, '/auth/config');
    expect(ssrFetchMock).toHaveBeenNthCalledWith(2, '/auth/me');
    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected bootstrap success');
    }

    expect(result.routeState.kind).toBe('AUTHENTICATED_MEMBER');
    expect(result.me?.user.email).toBe('user@example.com');
  });

  it('treats 401 from /auth/me as PUBLIC_ENTRY instead of a fatal bootstrap error', async () => {
    ssrFetchMock.mockImplementation((path: string) => {
      if (path === '/auth/config') {
        return jsonResponse(makeConfig());
      }

      if (path === '/auth/me') {
        return jsonResponse(
          {
            error: {
              code: 'UNAUTHORIZED',
              message: 'No active session.',
            },
          },
          { status: 401, statusText: 'Unauthorized' },
        );
      }

      throw new Error(`Unexpected path: ${path}`);
    });

    const result = await loadAuthBootstrap();

    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected bootstrap success');
    }

    expect(result.me).toBeNull();
    expect(result.routeState.kind).toBe('PUBLIC_ENTRY');
  });

  it('skips /auth/me when /auth/config says the tenant is unavailable', async () => {
    ssrFetchMock.mockResolvedValueOnce(
      jsonResponse(
        makeConfig({
          isActive: false,
          publicSignupEnabled: false,
          signupAllowed: false,
          allowedSso: [],
        }),
      ),
    );

    const result = await loadAuthBootstrap();

    expect(ssrFetchMock).toHaveBeenCalledTimes(1);
    expect(ssrFetchMock).toHaveBeenCalledWith('/auth/config');
    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected bootstrap success');
    }

    expect(result.me).toBeNull();
    expect(result.routeState.kind).toBe('TENANT_UNAVAILABLE');
  });

  it('returns a failure result when /auth/config itself fails', async () => {
    ssrFetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          error: {
            code: 'HTTP_503',
            message: 'Upstream unavailable',
          },
        },
        { status: 503, statusText: 'Service Unavailable' },
      ),
    );

    const result = await loadAuthBootstrap();

    expect(result.ok).toBe(false);

    if (result.ok) {
      throw new Error('Expected bootstrap failure');
    }

    expect(result.error).toBeInstanceOf(ApiHttpError);
    expect(result.error.message).toBe('Upstream unavailable');
  });
});
