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

import OperationalAccessSettingsPage from '../../../src/app/admin/settings/operational-access/page';

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
    nextAction: null,
    cards: [
      {
        key: 'operationalAccess',
        title: 'Operational Access',
        description:
          'Safe admin shell for future Agent grants and coverage. No runtime access grants are shipped yet.',
        href: '/admin/settings/operational-access',
        classification: 'LIVE_NON_GATING',
        status: 'MANAGEMENT',
        warnings: [
          'Operational Access is enabled for this tenant, but grants, coverage, resolver behavior, and runtime Agent visibility are not shipped yet.',
        ],
        isRequired: false,
        requiredReason: null,
      },
    ],
    ...overrides,
  };
}

describe('OperationalAccessSettingsPage', () => {
  it('renders the safe shell when the backend overview exposes the capability card', async () => {
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

    const html = renderToStaticMarkup(await OperationalAccessSettingsPage());

    expect(html).toContain('Operational Access');
    expect(html).toContain('Capability enabled — configuration not shipped');
    expect(html).toContain('Agent group membership remains provisioning-only.');
    expect(html).toContain(
      'No Effective Access Resolver or runtime visibility changes are shipped.',
    );
    expect(html).toContain('/admin/settings/access remains Access &amp; Security.');
  });

  it('returns not found when the backend overview does not expose the capability card', async () => {
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
      data: makeOverview({ cards: [] }),
    });

    await expect(OperationalAccessSettingsPage()).rejects.toThrow('NOT_FOUND');
    expect(notFoundMock).toHaveBeenCalled();
  });

  it('redirects Agent/User route states away from the admin-only shell', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_WORKSPACE',
        config: makeConfig(),
        me: makeMe({ membership: { id: 'membership-1', role: 'AGENT' } }),
      },
      me: makeMe({ membership: { id: 'membership-1', role: 'AGENT' } }),
    });

    await expect(OperationalAccessSettingsPage()).rejects.toThrow('REDIRECT:/app');
    expect(redirectMock).toHaveBeenCalledWith('/app');
  });

  it('renders an explicit backend capability-read error instead of local fallback truth', async () => {
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

    const html = renderToStaticMarkup(await OperationalAccessSettingsPage());

    expect(html).toContain('GET /settings/overview');
    expect(html).toContain('capability boundary');
    expect(html).toContain('settings overview failed');
  });
});
