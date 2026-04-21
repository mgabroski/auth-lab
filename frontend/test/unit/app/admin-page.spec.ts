import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';
import type { SettingsBootstrapResponse } from '../../../src/shared/settings/contracts';

const { loadAuthBootstrapMock, loadSettingsBootstrapMock, redirectMock } = vi.hoisted(() => ({
  loadAuthBootstrapMock: vi.fn(),
  loadSettingsBootstrapMock: vi.fn(),
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
  loadSettingsBootstrap: loadSettingsBootstrapMock,
}));

vi.mock('@/shared/auth/components/authenticated-shell', () => ({
  AuthenticatedShell: ({ title, children }: { title: string; children: React.ReactNode }) =>
    React.createElement('section', null, React.createElement('h1', null, title), children),
}));

vi.mock('@/shared/auth/components/workspace-setup-banner', () => ({
  WorkspaceSetupBanner: ({ showSetupBanner }: { showSetupBanner: boolean }) =>
    showSetupBanner ? React.createElement('div', null, 'Workspace setup banner visible') : null,
}));

import AdminPage from '../../../src/app/admin/page';

function makeConfig(overrides: Partial<ConfigResponse['tenant']> = {}): ConfigResponse {
  return {
    tenant: {
      name: 'GoodWill Open',
      isActive: true,
      publicSignupEnabled: true,
      signupAllowed: true,
      allowedSso: ['google'],
      setupCompleted: true,
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

function makeSettingsBootstrap(
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

describe('AdminPage', () => {
  it('renders the banner from Settings bootstrap truth instead of auth config.setupCompleted', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig({ setupCompleted: true }),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadSettingsBootstrapMock.mockResolvedValue({
      ok: true,
      data: makeSettingsBootstrap({ showSetupBanner: true }),
    });

    const html = renderToStaticMarkup(await AdminPage());

    expect(html).toContain('Workspace setup banner visible');
    expect(html).toContain('Open workspace settings');
  });

  it('does not render the banner when Settings bootstrap says setup is complete', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig({ setupCompleted: false }),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadSettingsBootstrapMock.mockResolvedValue({
      ok: true,
      data: makeSettingsBootstrap({
        overallStatus: 'COMPLETE',
        showSetupBanner: false,
        nextAction: null,
      }),
    });

    const html = renderToStaticMarkup(await AdminPage());

    expect(html).not.toContain('Workspace setup banner visible');
    expect(html).toContain('Admin landing ready');
  });

  it('renders an explicit Settings bootstrap error instead of falling back to auth scaffold truth', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig({ setupCompleted: false }),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadSettingsBootstrapMock.mockResolvedValue({
      ok: false,
      error: new Error('settings bootstrap failed'),
    });

    const html = renderToStaticMarkup(await AdminPage());

    expect(html).toContain('Workspace settings status is unavailable.');
    expect(html).toContain('settings bootstrap failed');
    expect(html).not.toContain('Workspace setup banner visible');
  });

  it('redirects non-admin route states away from /admin', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_MEMBER',
        config: makeConfig(),
        me: makeMe({ membership: { id: 'membership-1', role: 'MEMBER' } }),
      },
      me: makeMe({ membership: { id: 'membership-1', role: 'MEMBER' } }),
    });

    await expect(AdminPage()).rejects.toThrow('REDIRECT:/app');
    expect(redirectMock).toHaveBeenCalledWith('/app');
  });
});
