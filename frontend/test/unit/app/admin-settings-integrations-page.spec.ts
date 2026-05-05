import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';
import type { IntegrationsSettingsResponse } from '../../../src/shared/settings/contracts';

const { loadAuthBootstrapMock, loadIntegrationsSettingsMock, redirectMock } = vi.hoisted(() => ({
  loadAuthBootstrapMock: vi.fn(),
  loadIntegrationsSettingsMock: vi.fn(),
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
  loadIntegrationsSettings: loadIntegrationsSettingsMock,
}));

vi.mock('@/shared/auth/components/authenticated-shell', () => ({
  AuthenticatedShell: ({ title, children }: { title: string; children: React.ReactNode }) =>
    React.createElement('section', null, React.createElement('h1', null, title), children),
}));

vi.mock('@/shared/settings/components/integrations-settings-view', () => ({
  IntegrationsSettingsView: ({ data }: { data: IntegrationsSettingsResponse }) =>
    React.createElement(
      'article',
      null,
      `${data.sectionKey}:${data.title}:${data.ssoIntegrations.length}`,
    ),
}));

import AdminSettingsIntegrationsPage from '../../../src/app/admin/settings/integrations/page';

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

function makeIntegrations(
  overrides: Partial<IntegrationsSettingsResponse> = {},
): IntegrationsSettingsResponse {
  return {
    sectionKey: 'integrations',
    title: 'Integrations',
    description: 'Informational integrations.',
    status: 'NOT_STARTED',
    version: 1,
    cpRevision: 2,
    ssoIntegrations: [
      {
        integrationKey: 'integration.sso.google',
        providerKey: 'google',
        title: 'Google SSO Integration',
        description: 'Informational Google SSO.',
        displayStatus: 'BLOCKED',
        statusLabel: 'Blocked',
        visible: true,
        cpAllowed: true,
        loginMethodEnabled: true,
        tenantConfigurationAvailable: false,
        credentialEntryAvailable: false,
        connectionFlowAvailable: false,
        runtimeReadiness: {
          status: 'SNAPSHOT_UNAVAILABLE',
          checkedAt: '2026-04-21T00:00:00.000Z',
          detail: 'missing snapshot',
        },
        warnings: ['Readiness unavailable.'],
        blockers: [],
        resolutionHint: 'Review readiness.',
        accessDependency: {
          loginMethodKey: 'auth.login.google',
          enabled: true,
          description: 'Google login enabled.',
        },
      },
    ],
    deferredIntegrations: [],
    marketplace: {
      integrationKey: 'integration.marketplace',
      treatment: 'PLACEHOLDER_ONLY',
      visible: false,
      reason: 'Marketplace is placeholder-only.',
    },
    warnings: ['Readiness unavailable.'],
    nextAction: null,
    ...overrides,
  };
}

describe('AdminSettingsIntegrationsPage', () => {
  it('renders the real Integrations page from the backend DTO', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadIntegrationsSettingsMock.mockResolvedValue({
      ok: true,
      data: makeIntegrations(),
    });

    const html = renderToStaticMarkup(await AdminSettingsIntegrationsPage());

    expect(html).toContain('Integrations');
    expect(html).toContain('← Back to workspace settings');
    expect(html).toContain('integrations:Integrations:1');
  });

  it('renders an explicit error card when GET /settings/integrations fails', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadIntegrationsSettingsMock.mockResolvedValue({
      ok: false,
      error: new Error('settings integrations failed'),
    });

    const html = renderToStaticMarkup(await AdminSettingsIntegrationsPage());

    expect(html).toContain('Integrations are unavailable');
    expect(html).toContain('GET /settings/integrations');
    expect(html).toContain('settings integrations failed');
  });

  it('redirects non-admin route states away from /admin/settings/integrations', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_MEMBER',
        config: makeConfig(),
        me: makeMe({ membership: { id: 'membership-1', role: 'MEMBER' } }),
      },
      me: makeMe({ membership: { id: 'membership-1', role: 'MEMBER' } }),
    });

    await expect(AdminSettingsIntegrationsPage()).rejects.toThrow('REDIRECT:/app');
    expect(redirectMock).toHaveBeenCalledWith('/app');
  });
});
