import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';
import type { AccessSettingsResponse } from '../../../src/shared/settings/contracts';

const { loadAuthBootstrapMock, loadAccessSettingsMock, redirectMock } = vi.hoisted(() => ({
  loadAuthBootstrapMock: vi.fn(),
  loadAccessSettingsMock: vi.fn(),
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
  loadAccessSettings: loadAccessSettingsMock,
}));

vi.mock('@/shared/auth/components/authenticated-shell', () => ({
  AuthenticatedShell: ({ title, children }: { title: string; children: React.ReactNode }) =>
    React.createElement('section', null, React.createElement('h1', null, title), children),
}));

vi.mock('@/shared/settings/components/access-settings-review', () => ({
  AccessSettingsReview: ({ initialData }: { initialData: AccessSettingsResponse }) =>
    React.createElement(
      'article',
      null,
      `${initialData.sectionKey}:${initialData.title}:${initialData.acknowledgeLabel}`,
    ),
}));

import AdminSettingsAccessPage from '../../../src/app/admin/settings/access/page';

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

function makeAccess(overrides: Partial<AccessSettingsResponse> = {}): AccessSettingsResponse {
  return {
    sectionKey: 'access',
    title: 'Access & Security',
    description: 'Review the platform-managed access envelope.',
    status: 'NOT_STARTED',
    version: 1,
    cpRevision: 2,
    canAcknowledge: true,
    acknowledgeLabel: 'Acknowledge & Mark Reviewed',
    groups: [
      {
        key: 'loginMethods',
        title: 'Login Methods',
        description: 'Platform-managed methods.',
        rows: [
          {
            key: 'password',
            label: 'Username & Password',
            value: 'Enabled',
            readOnly: true,
            managedBy: 'CONTROL_PLANE',
            status: 'READY',
            warning: null,
            blocker: null,
            resolutionHref: null,
          },
        ],
      },
    ],
    blockers: [],
    warnings: [],
    nextAction: {
      key: 'access',
      label: 'Review Access & Security',
      href: '/admin/settings/access',
    },
    ...overrides,
  };
}

describe('AdminSettingsAccessPage', () => {
  it('renders the real Access page from the backend DTO instead of the old shell route', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadAccessSettingsMock.mockResolvedValue({
      ok: true,
      data: makeAccess(),
    });

    const html = renderToStaticMarkup(await AdminSettingsAccessPage());

    expect(html).toContain('Access &amp; Security');
    expect(html).toContain('← Back to workspace settings');
    expect(html).toContain('access:Access &amp; Security:Acknowledge &amp; Mark Reviewed');
  });

  it('renders an explicit error card when GET /settings/access fails', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadAccessSettingsMock.mockResolvedValue({
      ok: false,
      error: new Error('settings access failed'),
    });

    const html = renderToStaticMarkup(await AdminSettingsAccessPage());

    expect(html).toContain('Access &amp; Security is unavailable');
    expect(html).toContain('GET /settings/access');
    expect(html).toContain('settings access failed');
  });

  it('redirects non-admin route states away from /admin/settings/access', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_MEMBER',
        config: makeConfig(),
        me: makeMe({ membership: { id: 'membership-1', role: 'MEMBER' } }),
      },
      me: makeMe({ membership: { id: 'membership-1', role: 'MEMBER' } }),
    });

    await expect(AdminSettingsAccessPage()).rejects.toThrow('REDIRECT:/app');
    expect(redirectMock).toHaveBeenCalledWith('/app');
  });
});
