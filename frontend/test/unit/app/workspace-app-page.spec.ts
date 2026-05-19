import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';

const { loadAuthBootstrapMock, redirectMock } = vi.hoisted(() => ({
  loadAuthBootstrapMock: vi.fn(),
  redirectMock: vi.fn((path: string) => {
    throw new Error(`REDIRECT:${path}`);
  }),
}));

vi.mock('next/navigation', () => ({
  redirect: redirectMock,
}));

vi.mock('@/shared/auth/bootstrap.server', () => ({
  loadAuthBootstrap: loadAuthBootstrapMock,
}));

vi.mock('@/shared/auth/components/authenticated-shell', () => ({
  AuthenticatedShell: ({
    title,
    subtitle,
    me,
    children,
  }: {
    title: string;
    subtitle: string;
    me: MeResponse;
    children: React.ReactNode;
  }) =>
    React.createElement(
      'section',
      { 'data-role': me.membership.role },
      React.createElement('h1', null, title),
      React.createElement('p', null, subtitle),
      children,
    ),
}));

import WorkspaceAppPage from '../../../src/app/app/page';

afterEach(() => {
  loadAuthBootstrapMock.mockReset();
  redirectMock.mockClear();
});

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
      email: 'user@example.com',
      name: 'Workspace User',
    },
    membership: {
      id: 'membership-1',
      role: 'USER',
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

describe('WorkspaceAppPage', () => {
  it('renders the authenticated workspace shell for USER sessions without admin navigation', async () => {
    const userMe = makeMe({ membership: { id: 'membership-1', role: 'USER' } });

    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_WORKSPACE',
        config: makeConfig(),
        me: userMe,
      },
      me: userMe,
    });

    const html = renderToStaticMarkup(await WorkspaceAppPage());

    expect(html).toContain('Workspace');
    expect(html).toContain('Authenticated workspace shell for User and Agent sessions.');
    expect(html).toContain('Your self-service workspace is available.');
    expect(html).not.toContain('/admin/settings');
    expect(html).not.toContain('Manage invites');
    expect(html).not.toContain('People &amp; Teams');
  });

  it('renders a safe neutral workspace state for AGENT sessions without fake operational modules', async () => {
    const agentMe = makeMe({ membership: { id: 'membership-1', role: 'AGENT' } });

    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_WORKSPACE',
        config: makeConfig(),
        me: agentMe,
      },
      me: agentMe,
    });

    const html = renderToStaticMarkup(await WorkspaceAppPage());

    expect(html).toContain('Workspace');
    expect(html).toContain(
      'You do not currently have access to operational areas. Contact your administrator.',
    );
    expect(html).toContain('backend-resolved access');
    expect(html).not.toContain('Operational Access');
    expect(html).not.toContain('Access Grants');
    expect(html).not.toContain('Permissions');
    expect(html).not.toContain('Tasks');
    expect(html).not.toContain('Documents');
    expect(html).not.toContain('Checklists');
    expect(html).not.toContain('Responsible For');
    expect(html).not.toContain('Assigned Areas');
    expect(html).not.toContain('Oversight');
    expect(html).not.toContain('Temporary Coverage');
    expect(html).not.toContain('Special Access');
    expect(html).not.toContain('Managed People');
    expect(html).not.toContain('Effective Access Resolver');
    expect(html).not.toContain('/admin/settings');
  });

  it('redirects ADMIN route states away from the workspace shell', async () => {
    const adminMe = makeMe({ membership: { id: 'membership-1', role: 'ADMIN' } });

    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: adminMe,
      },
      me: adminMe,
    });

    await expect(WorkspaceAppPage()).rejects.toThrow('REDIRECT:/admin');
    expect(redirectMock).toHaveBeenCalledWith('/admin');
  });

  it('redirects unauthenticated route states to login', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'PUBLIC_ENTRY',
        config: makeConfig(),
        me: null,
      },
      me: null,
    });

    await expect(WorkspaceAppPage()).rejects.toThrow('REDIRECT:/auth/login');
    expect(redirectMock).toHaveBeenCalledWith('/auth/login');
  });
});
