import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { ApiHttpError } from '../../../src/shared/auth/api-errors';
import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';
import type { AccountSettingsResponse } from '../../../src/shared/settings/contracts';

const { loadAuthBootstrapMock, loadAccountSettingsMock, redirectMock, notFoundMock } = vi.hoisted(
  () => ({
    loadAuthBootstrapMock: vi.fn(),
    loadAccountSettingsMock: vi.fn(),
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
  loadAccountSettings: loadAccountSettingsMock,
}));

vi.mock('@/shared/auth/components/authenticated-shell', () => ({
  AuthenticatedShell: ({ title, children }: { title: string; children: React.ReactNode }) =>
    React.createElement('section', null, React.createElement('h1', null, title), children),
}));

vi.mock('@/shared/settings/components/account-settings-form', () => ({
  AccountSettingsForm: ({ initialData }: { initialData: AccountSettingsResponse }) =>
    React.createElement(
      'article',
      null,
      `${initialData.sectionKey}:${initialData.title}:${initialData.cards.length}`,
    ),
}));

import AdminSettingsAccountPage from '../../../src/app/admin/settings/account/page';

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

function makeAccount(overrides: Partial<AccountSettingsResponse> = {}): AccountSettingsResponse {
  return {
    sectionKey: 'account',
    title: 'Account Settings',
    description: 'Configure branding, structure, and calendar values.',
    status: 'IN_PROGRESS',
    cards: [
      {
        key: 'branding',
        title: 'Branding',
        description: 'Branding values.',
        status: 'COMPLETE',
        version: 2,
        cpRevision: 4,
        visibility: {
          logo: true,
          menuColor: true,
          fontColor: true,
          welcomeMessage: true,
        },
        values: {
          logoUrl: 'https://cdn.example.com/logo.svg',
          menuColor: '#0f172a',
          fontColor: '#ffffff',
          welcomeMessage: 'Welcome',
        },
      },
      {
        key: 'orgStructure',
        title: 'Organization Structure',
        description: 'Organization lists.',
        status: 'NOT_STARTED',
        version: 1,
        cpRevision: 4,
        visibility: {
          employers: true,
          locations: true,
        },
        values: {
          employers: [],
          locations: [],
        },
      },
      {
        key: 'calendar',
        title: 'Company Calendar',
        description: 'Observed dates.',
        status: 'NOT_STARTED',
        version: 1,
        cpRevision: 4,
        visibility: {
          allowed: true,
        },
        values: {
          observedDates: [],
        },
      },
    ],
    warnings: [],
    nextAction: {
      key: 'access',
      label: 'Review Access & Security',
      href: '/admin/settings/access',
    },
    ...overrides,
  };
}

describe('AdminSettingsAccountPage', () => {
  it('renders the real Account page from the backend DTO', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadAccountSettingsMock.mockResolvedValue({
      ok: true,
      data: makeAccount(),
    });

    const html = renderToStaticMarkup(await AdminSettingsAccountPage());

    expect(html).toContain('Account Settings');
    expect(html).toContain('← Back to workspace settings');
    expect(html).toContain('account:Account Settings:3');
  });

  it('renders an explicit error card when GET /settings/account fails', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadAccountSettingsMock.mockResolvedValue({
      ok: false,
      error: new Error('settings account failed'),
    });

    const html = renderToStaticMarkup(await AdminSettingsAccountPage());

    expect(html).toContain('Account Settings is unavailable');
    expect(html).toContain('GET /settings/account');
    expect(html).toContain('settings account failed');
  });

  it('treats a hidden account section as not found', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadAccountSettingsMock.mockResolvedValue({
      ok: false,
      error: new ApiHttpError({
        status: 404,
        code: 'HTTP_404',
        message: 'Account Settings is not available for this workspace.',
      }),
    });

    await expect(AdminSettingsAccountPage()).rejects.toThrow('NOT_FOUND');
    expect(notFoundMock).toHaveBeenCalled();
  });
});
