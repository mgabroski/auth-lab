import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';
import type { PeopleTeamsFoundationResponse } from '../../../src/shared/people-teams/contracts';

const { loadAuthBootstrapMock, loadPeopleTeamsFoundationMock, redirectMock } = vi.hoisted(() => ({
  loadAuthBootstrapMock: vi.fn(),
  loadPeopleTeamsFoundationMock: vi.fn(),
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

vi.mock('@/shared/people-teams/loaders', () => ({
  loadPeopleTeamsFoundation: loadPeopleTeamsFoundationMock,
}));

vi.mock('@/shared/auth/components/authenticated-shell', () => ({
  AuthenticatedShell: ({ title, children }: { title: string; children: React.ReactNode }) =>
    React.createElement('section', null, React.createElement('h1', null, title), children),
}));

vi.mock('@/shared/people-teams/components/people-teams-view', () => ({
  PeopleTeamsView: ({ initialData }: { initialData: PeopleTeamsFoundationResponse }) =>
    React.createElement(
      'div',
      null,
      `people-teams:${initialData.groups.length}:${initialData.people.length}`,
    ),
}));

import AdminSettingsPeopleTeamsPage from '../../../src/app/admin/settings/people-teams/page';

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
    user: { id: 'user-1', email: 'admin@example.com', name: 'Admin User' },
    membership: { id: 'membership-1', role: 'ADMIN' },
    tenant: { id: 'tenant-1', key: 'goodwill-open', name: 'GoodWill Open' },
    session: { mfaVerified: true, emailVerified: true },
    nextAction: 'NONE',
    ...overrides,
  };
}

function makePeopleTeams(): PeopleTeamsFoundationResponse {
  return {
    groups: [
      {
        id: 'group-1',
        name: 'HR Agents',
        normalizedName: 'hr agents',
        description: 'Human resources group',
        level: 'AGENT',
        status: 'ACTIVE',
        memberCount: 1,
        createdAt: '2026-05-14T00:00:00.000Z',
        updatedAt: '2026-05-14T00:00:00.000Z',
        archivedAt: null,
      },
    ],
    people: [
      {
        membershipId: 'membership-1',
        userId: 'user-1',
        email: 'admin@example.com',
        name: 'Admin User',
        role: 'ADMIN',
        status: 'ACTIVE',
      },
    ],
  };
}

describe('AdminSettingsPeopleTeamsPage', () => {
  it('renders the People & Teams management page for admins', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadPeopleTeamsFoundationMock.mockResolvedValue({
      ok: true,
      data: makePeopleTeams(),
    });

    const html = renderToStaticMarkup(await AdminSettingsPeopleTeamsPage());

    expect(html).toContain('People &amp; Teams');
    expect(html).toContain('← Back to workspace settings');
    expect(html).toContain('people-teams:1:1');
  });

  it('renders an explicit error if the backend foundation cannot load', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadPeopleTeamsFoundationMock.mockResolvedValue({
      ok: false,
      error: new Error('people teams failed'),
    });

    const html = renderToStaticMarkup(await AdminSettingsPeopleTeamsPage());

    expect(html).toContain('People &amp; Teams is unavailable');
    expect(html).toContain('GET /people-teams/groups');
    expect(html).toContain('people teams failed');
  });

  it('redirects non-admin route states away from People & Teams', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_WORKSPACE',
        config: makeConfig(),
        me: makeMe({ membership: { id: 'membership-1', role: 'USER' } }),
      },
      me: makeMe({ membership: { id: 'membership-1', role: 'USER' } }),
    });

    await expect(AdminSettingsPeopleTeamsPage()).rejects.toThrow('REDIRECT:/app');
    expect(redirectMock).toHaveBeenCalledWith('/app');
  });
});
