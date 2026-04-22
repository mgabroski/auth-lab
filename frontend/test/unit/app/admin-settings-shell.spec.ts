import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';
import type { SettingsOverviewResponse } from '../../../src/shared/settings/contracts';

const { loadAuthBootstrapMock, loadSettingsOverviewMock, redirectMock, notFoundMock } = vi.hoisted(
  () => ({
    loadAuthBootstrapMock: vi.fn(),
    loadSettingsOverviewMock: vi.fn(),
    redirectMock: vi.fn((path: string) => {
      throw new Error(`REDIRECT:${path}`);
    }),
    notFoundMock: vi.fn(() => {
      throw new Error('NOT_FOUND');
    }),
  }),
);

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
  loadSettingsOverview: loadSettingsOverviewMock,
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
        description: 'Required section.',
        href: '/admin/settings/access',
        classification: 'REQUIRED_GATING',
        status: 'IN_PROGRESS',
        warnings: [],
        isRequired: true,
      },
      {
        key: 'account',
        title: 'Account Settings',
        description: 'Live non-gating section.',
        href: '/admin/settings/account',
        classification: 'LIVE_NON_GATING',
        status: 'NOT_STARTED',
        warnings: [],
        isRequired: false,
      },
      {
        key: 'communications',
        title: 'Communications',
        description: 'Placeholder only.',
        href: '/admin/settings/communications',
        classification: 'PLACEHOLDER_ONLY',
        status: 'PLACEHOLDER',
        warnings: [],
        isRequired: false,
      },
      {
        key: 'modules',
        title: 'Modules',
        description: 'Navigation hub.',
        href: '/admin/settings/modules',
        classification: 'NAVIGATION_ONLY',
        status: 'NOT_STARTED',
        warnings: [],
        isRequired: false,
      },
    ],
    ...overrides,
  };
}

describe('SettingsRouteShellPage', () => {
  it('renders the communications placeholder route without inventing a live configuration surface', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadSettingsOverviewMock.mockResolvedValue({
      ok: true,
      data: makeOverview(),
    });

    const html = renderToStaticMarkup(
      await SettingsRouteShellPage({
        params: Promise.resolve({ slug: ['communications'] }),
      }),
    );

    expect(html).toContain('Communications');
    expect(html).toContain('This route is intentionally placeholder-only in the current repo.');
  });

  it('treats dedicated live section routes as not found for the shell catch-all', async () => {
    await expect(
      SettingsRouteShellPage({
        params: Promise.resolve({ slug: ['modules'] }),
      }),
    ).rejects.toThrow('NOT_FOUND');
    expect(notFoundMock).toHaveBeenCalled();
  });

  it('treats absent or unsupported routes as not found', async () => {
    await expect(
      SettingsRouteShellPage({
        params: Promise.resolve({ slug: ['permissions'] }),
      }),
    ).rejects.toThrow('NOT_FOUND');
    expect(notFoundMock).toHaveBeenCalled();
  });
});
