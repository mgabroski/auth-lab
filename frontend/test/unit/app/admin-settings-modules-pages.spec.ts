import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { ApiHttpError } from '../../../src/shared/auth/api-errors';

import type { ConfigResponse, MeResponse } from '../../../src/shared/auth/contracts';
import type {
  ModulesHubResponse,
  PersonalSettingsResponse,
} from '../../../src/shared/settings/contracts';

const {
  loadAuthBootstrapMock,
  loadModulesHubMock,
  loadPersonalSettingsMock,
  redirectMock,
  notFoundMock,
} = vi.hoisted(() => ({
  loadAuthBootstrapMock: vi.fn(),
  loadModulesHubMock: vi.fn(),
  loadPersonalSettingsMock: vi.fn(),
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
  loadModulesHub: loadModulesHubMock,
  loadPersonalSettings: loadPersonalSettingsMock,
}));

vi.mock('@/shared/auth/components/authenticated-shell', () => ({
  AuthenticatedShell: ({ title, children }: { title: string; children: React.ReactNode }) =>
    React.createElement('section', null, React.createElement('h1', null, title), children),
}));

vi.mock('@/shared/settings/components/modules-hub', () => ({
  ModulesHub: ({ data }: { data: ModulesHubResponse }) =>
    React.createElement('div', null, data.cards.map((card) => card.title).join(', ')),
}));

vi.mock('@/shared/settings/components/personal-settings-foundation', () => ({
  PersonalSettingsFoundation: ({ data }: { data: PersonalSettingsResponse }) =>
    React.createElement(
      'div',
      null,
      data.familyReview.families.map((family) => family.label).join(', '),
    ),
}));

import AdminSettingsModulesPage from '../../../src/app/admin/settings/modules/page';
import AdminSettingsPersonalPage from '../../../src/app/admin/settings/modules/personal/page';

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

function makeModules(overrides: Partial<ModulesHubResponse> = {}): ModulesHubResponse {
  return {
    title: 'Modules',
    description: 'Navigation-only modules hub.',
    cards: [
      {
        key: 'personal',
        title: 'Personal',
        description: 'Live module.',
        classification: 'LIVE',
        href: '/admin/settings/modules/personal',
        status: 'IN_PROGRESS',
        warnings: [],
        ctaLabel: 'Continue setup',
      },
      {
        key: 'documents',
        title: 'Documents',
        description: 'Placeholder module.',
        classification: 'PLACEHOLDER',
        href: null,
        status: 'PLACEHOLDER',
        warnings: [],
        ctaLabel: null,
      },
    ],
    visibleModuleKeys: ['personal', 'documents'],
    nextAction: {
      key: 'modules',
      label: 'Continue Personal setup',
      href: '/admin/settings/modules/personal',
    },
    ...overrides,
  };
}

function makePersonal(overrides: Partial<PersonalSettingsResponse> = {}): PersonalSettingsResponse {
  return {
    sectionKey: 'personal',
    title: 'Personal settings',
    description: 'Personal foundation.',
    status: 'NOT_STARTED',
    version: 1,
    cpRevision: 1,
    warnings: [],
    blockers: [],
    nextAction: {
      key: 'modules',
      label: 'Continue Personal setup',
      href: '/admin/settings/modules/personal',
    },
    moduleEnabled: true,
    familyReview: {
      title: 'Step 1 — Family review',
      description: 'Family review foundation.',
      summary: '2 allowed families are visible.',
      families: [
        {
          familyKey: 'identity',
          label: 'Identity',
          reviewDecision: 'UNREVIEWED',
          reviewStatus: 'NOT_STARTED',
          allowedFieldCount: 2,
          defaultSelectedFieldCount: 2,
          containsLockedRequiredFields: true,
          canExclude: false,
          requiredFieldKeys: ['person.first_name', 'person.last_name'],
          systemManagedFieldKeys: [],
          notes: ['Contains fields that cannot be excluded in later phases.'],
        },
      ],
    },
    fieldConfiguration: {
      key: 'fieldConfiguration',
      title: 'Field Configuration',
      description: 'Review the real field-rule foundation.',
      summary: '2 CP-allowed fields are grouped by family.',
      status: 'CURRENT_FOUNDATION',
      isLiveInCurrentRepo: true,
      hiddenVsExcluded: {
        hidden: 'Hidden means the field is not allowed by Control Plane.',
        excluded: 'Excluded means the field is CP-allowed but tenant-disabled later.',
      },
      conflictGuidance: {
        version: 1,
        cpRevision: 1,
        summary: 'Use the current section version and CP revision as the future conflict baseline.',
        notes: [
          'No Personal mutation route is shipped in this phase, so there is no fake save success path.',
        ],
      },
      families: [
        {
          familyKey: 'identity',
          label: 'Identity',
          canExclude: false,
          exclusionLockedReason: 'Contains minimum-required fields that cannot be excluded.',
          visibleFieldCount: 2,
          defaultSelectedFieldCount: 1,
          minimumRequiredFieldCount: 1,
          systemManagedFieldCount: 0,
          notes: ['Contains fields that cannot be excluded under the locked Personal rules.'],
          fields: [
            {
              familyKey: 'identity',
              fieldKey: 'person.first_name',
              label: 'First Name',
              notes: 'Required baseline field.',
              minimumRequired: 'required',
              isSystemManaged: false,
              presentationState: 'CONFIGURABLE',
              readiness: 'CP_DEFAULT_SELECTED',
              requiredRule: 'LOCKED_REQUIRED',
              maskingRule: 'TENANT_CHOICE_WHEN_INCLUDED',
              canBeExcludedLater: false,
              canToggleRequiredLater: false,
              canToggleMaskingLater: true,
              warnings: [],
              blockers: ['Required-floor field. It cannot be made optional or excluded.'],
            },
            {
              familyKey: 'identity',
              fieldKey: 'person.middle_name',
              label: 'Middle Name',
              notes: 'Optional identity field.',
              minimumRequired: 'none',
              isSystemManaged: false,
              presentationState: 'CONFIGURABLE',
              readiness: 'AVAILABLE_TO_INCLUDE',
              requiredRule: 'TENANT_CHOICE',
              maskingRule: 'TENANT_CHOICE_WHEN_INCLUDED',
              canBeExcludedLater: true,
              canToggleRequiredLater: true,
              canToggleMaskingLater: true,
              warnings: ['This field is CP-allowed but not currently default-selected.'],
              blockers: [],
            },
          ],
        },
      ],
    },
    sectionBuilder: {
      key: 'sectionBuilder',
      title: 'Section Builder',
      description: 'Future phase.',
      status: 'FUTURE_PHASE',
      isLiveInCurrentRepo: false,
      summary: 'Not live yet.',
    },
    ...overrides,
  };
}

describe('admin settings modules routes', () => {
  it('renders the real Modules hub page', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadModulesHubMock.mockResolvedValue({ ok: true, data: makeModules() });

    const html = renderToStaticMarkup(await AdminSettingsModulesPage());

    expect(html).toContain('Modules');
    expect(html).toContain('Personal, Documents');
  });

  it('renders the real Personal foundation page', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadPersonalSettingsMock.mockResolvedValue({ ok: true, data: makePersonal() });

    const html = renderToStaticMarkup(await AdminSettingsPersonalPage());

    expect(html).toContain('Personal settings');
    expect(html).toContain('Identity');
  });

  it('treats 404 Personal responses as not found', async () => {
    loadAuthBootstrapMock.mockResolvedValue({
      ok: true,
      routeState: {
        kind: 'AUTHENTICATED_ADMIN',
        config: makeConfig(),
        me: makeMe(),
      },
      me: makeMe(),
    });
    loadPersonalSettingsMock.mockResolvedValue({
      ok: false,
      error: new ApiHttpError({ status: 404, code: 'HTTP_404', message: 'Missing' }),
    });

    await expect(AdminSettingsPersonalPage()).rejects.toThrow('NOT_FOUND');
    expect(notFoundMock).toHaveBeenCalled();
  });
});
