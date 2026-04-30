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
    description: 'Configure Personal for your workspace.',
    status: 'NOT_STARTED',
    version: 1,
    cpRevision: 4,
    warnings: [],
    blockers: [],
    nextAction: {
      key: 'modules',
      label: 'Continue Personal setup',
      href: '/admin/settings/modules/personal',
    },
    progress: {
      reviewedFamiliesCount: 0,
      totalAllowedFamilies: 1,
      requiredFieldsReady: true,
      sectionAssignmentsReady: true,
      blockers: [],
    },
    familyReview: {
      key: 'familyReview',
      title: 'Family Review',
      description: 'Family review.',
      summary: '0 of 1 allowed families have been saved.',
      status: 'NOT_STARTED',
      families: [
        {
          familyKey: 'identity',
          label: 'Identity',
          reviewDecision: 'IN_USE',
          reviewStatus: 'REQUIRES_SAVE',
          isAllowed: true,
          canExclude: false,
          lockedReason:
            'This family contains required-floor or system-managed fields and must stay in use.',
          allowedFieldCount: 2,
          includedFieldCount: 2,
          requiredFieldKeys: ['person.first_name'],
          notes: ['This family remains locked in use under the workspace baseline.'],
          warnings: [],
          blockers: [],
        },
      ],
    },
    fieldConfiguration: {
      key: 'fieldConfiguration',
      title: 'Field Configuration',
      description: 'Configure fields.',
      summary: 'Required-floor fields are currently configured.',
      status: 'IN_PROGRESS',
      hiddenVsExcluded: {
        hidden: 'Hidden means not CP-allowed and never shown in the tenant UI.',
        excluded: 'Excluded means CP-allowed but tenant-chosen not in use.',
      },
      families: [
        {
          familyKey: 'identity',
          label: 'Identity',
          reviewDecision: 'IN_USE',
          canExclude: false,
          exclusionLockedReason:
            'This family contains required-floor or system-managed fields and must stay in use.',
          visibleFieldCount: 2,
          includedFieldCount: 2,
          minimumRequiredFieldCount: 1,
          systemManagedFieldCount: 0,
          notes: ['This family remains locked in use under the workspace baseline.'],
          fields: [
            {
              familyKey: 'identity',
              fieldKey: 'person.first_name',
              label: 'First Name',
              notes: 'Required baseline field.',
              minimumRequired: 'required',
              isSystemManaged: false,
              included: true,
              required: true,
              masked: false,
              includeRule: 'LOCKED_INCLUDED',
              requiredRule: 'LOCKED_REQUIRED',
              maskingRule: 'TENANT_CHOICE',
              canToggleInclude: false,
              canToggleRequired: false,
              canToggleMasking: true,
              warnings: [],
              blockers: [],
            },
            {
              familyKey: 'identity',
              fieldKey: 'person.middle_name',
              label: 'Middle Name',
              notes: 'Optional identity field.',
              minimumRequired: 'none',
              isSystemManaged: false,
              included: true,
              required: false,
              masked: false,
              includeRule: 'TENANT_CHOICE',
              requiredRule: 'TENANT_CHOICE',
              maskingRule: 'TENANT_CHOICE',
              canToggleInclude: true,
              canToggleRequired: true,
              canToggleMasking: true,
              warnings: [],
              blockers: [],
            },
          ],
        },
      ],
    },
    sectionBuilder: {
      key: 'sectionBuilder',
      title: 'Section Builder',
      description: 'Simple sections.',
      summary: '1 section is ready for review and save.',
      status: 'IN_PROGRESS',
      emptySectionSaveBlocked: true,
      removeOnlyWhenEmpty: true,
      sections: [
        {
          sectionId: 'generated-identity',
          name: 'Identity',
          order: 0,
          fieldCount: 2,
          fields: [
            { fieldKey: 'person.first_name', familyKey: 'identity', label: 'First Name', order: 0 },
            {
              fieldKey: 'person.middle_name',
              familyKey: 'identity',
              label: 'Middle Name',
              order: 1,
            },
          ],
        },
      ],
    },
    conflictGuidance: {
      summary:
        'If a Personal save returns a conflict, keep your local draft, refetch the latest server DTO, and decide how to reconcile before saving again.',
      notes: ['There is no silent auto-merge or silent retry for Personal.'],
    },
    saveActionLabel: 'Save Personal Configuration',
    stickySaveLabel: 'Save Personal Configuration',
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

  it('renders the real Personal builder page', async () => {
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
