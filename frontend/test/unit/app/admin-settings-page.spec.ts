import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';
import type { SettingsOverviewResponse } from '../../../src/shared/settings/contracts';

const { loadAuthBootstrapMock, loadSettingsOverviewMock, redirectMock } = vi.hoisted(() => ({
  loadAuthBootstrapMock: vi.fn(),
  loadSettingsOverviewMock: vi.fn(),
  redirectMock: vi.fn((path: string) => {
    throw new Error(`REDIRECT:${path}`);
  }),
}));

vi.mock('next/navigation', () => ({
  redirect: redirectMock,
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

vi.mock('@/shared/settings/components/settings-overview-card', () => ({
  SettingsOverviewCard: ({ card }: { card: { title: string; key: string } }) =>
    React.createElement('article', null, `${card.key}:${card.title}`),
}));

vi.mock('@/shared/settings/components/settings-status-chip', () => ({
  SettingsStatusChip: ({ status }: { status: string }) => React.createElement('span', null, status),
}));

import AdminSettingsPage from '../../../src/app/admin/settings/page';

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
        description: 'Optional live section.',
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
    ],
    ...overrides,
  };
}

describe('AdminSettingsPage', () => {
  it('renders the Settings overview grouping and next-action callout from the real DTO', async () => {
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

    const html = renderToStaticMarkup(await AdminSettingsPage());

    expect(html).toContain('Continue workspace setup');
    expect(html).toContain('Review Access &amp; Security');
    expect(html).toContain('Required sections');
    expect(html).toContain('Optional sections');
    expect(html).toContain('access:Access &amp; Security');
    expect(html).toContain('communications:Communications');
    expect(html).not.toContain('Permissions');
  });

  it('renders an explicit overview error instead of falling back to auth scaffold truth', async () => {
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
      ok: false,
      error: new Error('settings overview failed'),
    });

    const html = renderToStaticMarkup(await AdminSettingsPage());

    expect(html).toContain('Workspace settings overview is unavailable');
    expect(html).toContain('settings overview failed');
    expect(html).toContain('not rendering a fallback');
  });

  it('redirects non-admin route states away from /admin/settings', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_MEMBER',
        config: makeConfig(),
        me: makeMe({ membership: { id: 'membership-1', role: 'MEMBER' } }),
      },
      me: makeMe({ membership: { id: 'membership-1', role: 'MEMBER' } }),
    });

    await expect(AdminSettingsPage()).rejects.toThrow('REDIRECT:/app');
    expect(redirectMock).toHaveBeenCalledWith('/app');
  });
});
