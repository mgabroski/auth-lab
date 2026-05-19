import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';
import type { OperationalAccessFoundationResponse } from '../../../src/shared/operational-access/contracts';
import type { SettingsOverviewResponse } from '../../../src/shared/settings/contracts';

const {
  loadAuthBootstrapMock,
  loadOperationalAccessFoundationMock,
  loadSettingsOverviewMock,
  redirectMock,
  notFoundMock,
} = vi.hoisted(() => ({
  loadAuthBootstrapMock: vi.fn(),
  loadOperationalAccessFoundationMock: vi.fn(),
  loadSettingsOverviewMock: vi.fn(),
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
  loadSettingsOverview: loadSettingsOverviewMock,
}));

vi.mock('@/shared/operational-access/loaders', () => ({
  loadOperationalAccessFoundation: loadOperationalAccessFoundationMock,
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

function makeOperationalAccessFoundation(): OperationalAccessFoundationResponse {
  return {
    catalog: {
      actions: [
        {
          key: 'tasks.manage',
          label: 'Manage tasks',
          description:
            'Can work on task records that match this grant and future backend visibility checks.',
          category: 'Tasks',
          allowedPrimaryWhere: ['RESPONSIBLE_FOR'],
          allowedWhichRecords: ['open_tasks'],
        },
      ],
      primaryWhere: [
        {
          key: 'RESPONSIBLE_FOR',
          label: 'Responsible For',
          description: 'The group normally works for exact people each Agent is responsible for.',
        },
      ],
      whichRecords: [
        {
          key: 'open_tasks',
          label: 'Open tasks',
          description: 'Only open task records inside the selected Primary Where.',
          category: 'Tasks',
        },
      ],
      coverage: {
        assignedAreas: {
          available: false,
          reason: 'Assigned Areas requires stable employer/location pair IDs.',
        },
        responsibleFor: {
          available: true,
          targetType: 'tenant_membership',
          reason: 'Responsible For can safely use active tenant membership IDs.',
        },
      },
      deferred: ['Backend runtime visibility decisions and module consumers are deferred.'],
    },
    groups: [
      {
        id: 'group-1',
        name: 'Managers',
        description: 'Operational managers',
        level: 'AGENT',
        status: 'ACTIVE',
        memberCount: 2,
        grantCount: 1,
        responsibleForAssignmentCount: 3,
      },
    ],
    people: [],
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
          'Operational Access is enabled for this tenant, but grants, coverage, backend runtime visibility behavior, and runtime Agent visibility are not shipped yet.',
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
    loadOperationalAccessFoundationMock.mockResolvedValue({
      ok: true,
      data: makeOperationalAccessFoundation(),
    });

    const html = renderToStaticMarkup(await OperationalAccessSettingsPage());

    expect(html).toContain('Operational Access');
    expect(html).toContain('Operational Access configuration foundation');
    expect(html).toContain('What this group can do');
    expect(html).toContain('Where this group normally works');
    expect(html).toContain('Which records');
    expect(html).toContain('Managers');
    expect(html).toContain('Manage tasks');
    expect(html).toContain('No runtime visibility changes are shipped.');
    expect(html).not.toContain('Effective Access Resolver');
    expect(html).not.toContain('resolver');
    expect(html).not.toContain('permission engine');
    expect(html).not.toContain('ABAC');
    expect(html).not.toContain('IAM');
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

  it('renders an explicit Operational Access read error instead of local fallback truth', async () => {
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
    loadOperationalAccessFoundationMock.mockResolvedValue({
      ok: false,
      error: new Error('operational access failed'),
    });

    const html = renderToStaticMarkup(await OperationalAccessSettingsPage());

    expect(html).toContain('Operational Access configuration is unavailable');
    expect(html).toContain(
      'not rendering fallback group, action, Primary Where, Which Records, or coverage truth',
    );
    expect(html).toContain('operational access failed');
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
