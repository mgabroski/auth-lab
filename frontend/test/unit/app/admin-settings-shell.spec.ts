import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';
import type { PlaceholderPageResponse } from '../../../src/shared/settings/contracts';

const { loadAuthBootstrapMock, loadCommunicationsPlaceholderMock, redirectMock, notFoundMock } =
  vi.hoisted(() => ({
    loadAuthBootstrapMock: vi.fn(),
    loadCommunicationsPlaceholderMock: vi.fn(),
    redirectMock: vi.fn((path: string) => {
      throw new Error(`REDIRECT:${path}`);
    }),
    notFoundMock: vi.fn(() => {
      throw new Error('NOT_FOUND');
    }),
  }));

vi.mock('next/navigation', () => ({
  redirect: redirectMock,
  notFound: notFoundMock,
}));

vi.mock('next/link', () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) =>
    React.createElement('a', { href }, children),
}));

vi.mock('@/shared/auth/bootstrap.server', () => ({
  loadAuthBootstrap: loadAuthBootstrapMock,
}));

vi.mock('@/shared/settings/loaders', () => ({
  loadCommunicationsPlaceholder: loadCommunicationsPlaceholderMock,
}));

vi.mock('@/shared/auth/components/authenticated-shell', () => ({
  AuthenticatedShell: ({ title, children }: { title: string; children: React.ReactNode }) =>
    React.createElement('section', null, React.createElement('h1', null, title), children),
}));

vi.mock('@/shared/settings/components/settings-status-chip', () => ({
  SettingsStatusChip: ({ status }: { status: string }) => React.createElement('span', null, status),
}));

import SettingsRouteShellPage from '../../../src/app/admin/settings/[...slug]/page';

function makeConfig(overrides: Partial<ConfigResponse['tenant']> = {}): ConfigResponse {
  return {
    tenant: {
      name: 'GoodWill Open',
      isActive: true,
      publicSignupEnabled: true,
      signupAllowed: true,
      allowedSso: ['google'],
      setupCompleted: false,
      ...overrides,
    },
  };
}

function makeMe(overrides: Partial<MeResponse> = {}): MeResponse {
  return {
    user: {
      id: 'user-1',
      email: 'admin@example.com',
      name: 'Admin User',
    },
    membership: {
      id: 'membership-1',
      role: 'ADMIN',
    },
    tenant: {
      id: 'tenant-1',
      key: 'goodwill-open',
      name: 'GoodWill Open',
    },
    session: {
      mfaVerified: true,
      emailVerified: true,
    },
    nextAction: 'NONE',
    ...overrides,
  };
}

function makePlaceholder(
  overrides: Partial<PlaceholderPageResponse> = {},
): PlaceholderPageResponse {
  return {
    key: 'communications',
    title: 'Communications',
    status: 'PLACEHOLDER',
    treatment: 'PLACEHOLDER_ROUTE_ONLY',
    description:
      'Communications is intentionally placeholder-only in v1. There is no tenant configuration surface on this page.',
    liveConfigurationAvailable: false,
    mutationEndpointsAvailable: false,
    notes: [
      'Email templates are not configurable in v1.',
      'Notification rules are not configurable in v1.',
      'No setup action is required here for workspace completion.',
    ],
    backHref: '/admin/settings',
    ...overrides,
  };
}

describe('SettingsRouteShellPage', () => {
  it('renders the communications placeholder route from the Settings placeholder DTO', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadCommunicationsPlaceholderMock.mockResolvedValue({
      ok: true,
      data: makePlaceholder(),
    });

    const html = renderToStaticMarkup(
      await SettingsRouteShellPage({
        params: Promise.resolve({ slug: ['communications'] }),
      }),
    );

    expect(html).toContain('Communications');
    expect(html).toContain('Email templates are not configurable in v1.');
    expect(html).toContain('Notification rules are not configurable in v1.');
    expect(html).toContain('Live configuration available: no');
    expect(html).toContain('Mutation endpoints available: no');
  });

  it('renders an explicit placeholder-load error instead of inventing fallback copy', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadCommunicationsPlaceholderMock.mockResolvedValue({
      ok: false,
      error: new Error('settings communications failed'),
    });

    const html = renderToStaticMarkup(
      await SettingsRouteShellPage({
        params: Promise.resolve({ slug: ['communications'] }),
      }),
    );

    expect(html).toContain('GET /settings/communications');
    expect(html).toContain('not inventing a local fallback');
    expect(html).toContain('settings communications failed');
  });

  it('treats dedicated live section routes as not found for the shell catch-all', async () => {
    await expect(
      SettingsRouteShellPage({
        params: Promise.resolve({ slug: ['integrations'] }),
      }),
    ).rejects.toThrow('NOT_FOUND');
    expect(notFoundMock).toHaveBeenCalled();
  });

  it('treats absent Permissions as not found', async () => {
    await expect(
      SettingsRouteShellPage({
        params: Promise.resolve({ slug: ['permissions'] }),
      }),
    ).rejects.toThrow('NOT_FOUND');
    expect(notFoundMock).toHaveBeenCalled();
  });

  it('treats Workspace Experience as overview-card-only with no route', async () => {
    await expect(
      SettingsRouteShellPage({
        params: Promise.resolve({ slug: ['workspace-experience'] }),
      }),
    ).rejects.toThrow('NOT_FOUND');
    expect(notFoundMock).toHaveBeenCalled();
  });

  it('treats Communications child routes as not found', async () => {
    await expect(
      SettingsRouteShellPage({
        params: Promise.resolve({ slug: ['communications', 'email-templates'] }),
      }),
    ).rejects.toThrow('NOT_FOUND');
    expect(notFoundMock).toHaveBeenCalled();
  });
});
