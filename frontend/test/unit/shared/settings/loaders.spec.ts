import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiHttpError } from '../../../../src/shared/auth/api-errors';
import type {
  AccessSettingsResponse,
  AccountSettingsResponse,
  ModulesHubResponse,
  PersonalSettingsResponse,
  SettingsBootstrapResponse,
  SettingsOverviewResponse,
} from '../../../../src/shared/settings/contracts';

const { ssrFetchMock, serverLoggerErrorMock, serverLoggerInfoMock, serverLoggerWarnMock } =
  vi.hoisted(() => ({
    ssrFetchMock: vi.fn(),
    serverLoggerErrorMock: vi.fn(),
    serverLoggerInfoMock: vi.fn(),
    serverLoggerWarnMock: vi.fn(),
  }));

vi.mock('@/shared/ssr-api-client', () => ({
  ssrFetch: ssrFetchMock,
}));

vi.mock('@/shared/server/logger', () => ({
  serverLogger: {
    error: serverLoggerErrorMock,
    info: serverLoggerInfoMock,
    warn: serverLoggerWarnMock,
  },
}));

import {
  loadAccessSettings,
  loadAccountSettings,
  loadModulesHub,
  loadPersonalSettings,
  loadSettingsBootstrap,
  loadSettingsOverview,
} from '../../../../src/shared/settings/loaders';

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: init?.status ?? 200,
    statusText: init?.statusText,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
}

function makeBootstrap(
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

function makeAccess(overrides: Partial<AccessSettingsResponse> = {}): AccessSettingsResponse {
  return {
    sectionKey: 'access',
    title: 'Access & Security',
    description: 'Review the access envelope.',
    status: 'IN_PROGRESS',
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

function makeOverview(overrides: Partial<SettingsOverviewResponse> = {}): SettingsOverviewResponse {
  return {
    overallStatus: 'IN_PROGRESS',
    nextAction: {
      key: 'access',
      label: 'Review Access & Security',
      href: '/admin/settings/access',
    },
    cards: [
      {
        key: 'access',
        title: 'Access & Security',
        description: 'Review the access envelope.',
        href: '/admin/settings/access',
        classification: 'REQUIRED_GATING',
        status: 'IN_PROGRESS',
        warnings: [],
        isRequired: true,
      },
    ],
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
    ],
    visibleModuleKeys: ['personal'],
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
afterEach(() => {
  ssrFetchMock.mockReset();
  serverLoggerErrorMock.mockReset();
  serverLoggerInfoMock.mockReset();
  serverLoggerWarnMock.mockReset();
});

describe('settings loaders', () => {
  it('loadSettingsBootstrap calls the Settings-native bootstrap endpoint with SSR headers', async () => {
    ssrFetchMock.mockResolvedValueOnce(jsonResponse(makeBootstrap()));

    const result = await loadSettingsBootstrap();

    expect(ssrFetchMock).toHaveBeenCalledWith('/settings/bootstrap', {
      headers: {
        'X-Settings-Bootstrap': '1',
      },
    });
    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected settings bootstrap success');
    }

    expect(result.data.showSetupBanner).toBe(true);
    expect(result.data.nextAction?.href).toBe('/admin/settings/access');
  });

  it('loadSettingsOverview returns a failure result and logs when the endpoint fails', async () => {
    ssrFetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          error: {
            code: 'HTTP_503',
            message: 'Settings overview unavailable',
          },
        },
        { status: 503, statusText: 'Service Unavailable' },
      ),
    );

    const result = await loadSettingsOverview();

    expect(result.ok).toBe(false);

    if (result.ok) {
      throw new Error('Expected settings overview failure');
    }

    expect(result.error).toBeInstanceOf(ApiHttpError);
    expect(result.error.message).toBe('Settings overview unavailable');
    expect(serverLoggerErrorMock).toHaveBeenCalledWith(
      'settings.overview.load_failed',
      expect.objectContaining({
        event: 'settings.overview.load_failed',
        flow: 'ssr.settings',
        target: 'overview',
        status: 503,
        code: 'HTTP_503',
        error: 'Settings overview unavailable',
      }),
    );
  });

  it('loadSettingsOverview returns the overview payload when the backend succeeds', async () => {
    ssrFetchMock.mockResolvedValueOnce(jsonResponse(makeOverview()));

    const result = await loadSettingsOverview();

    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected settings overview success');
    }

    expect(result.data.cards).toHaveLength(1);
    expect(result.data.cards[0]?.key).toBe('access');
  });

  it('loadAccountSettings calls the real Account endpoint with SSR headers', async () => {
    ssrFetchMock.mockResolvedValueOnce(jsonResponse(makeAccount()));

    const result = await loadAccountSettings();

    expect(ssrFetchMock).toHaveBeenCalledWith('/settings/account', {
      headers: {
        'X-Settings-Account': '1',
      },
    });
    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected settings account success');
    }

    expect(result.data.sectionKey).toBe('account');
    expect(result.data.cards[0]?.key).toBe('branding');
  });

  it('loadAccessSettings calls the real Access endpoint with SSR headers', async () => {
    ssrFetchMock.mockResolvedValueOnce(jsonResponse(makeAccess()));

    const result = await loadAccessSettings();

    expect(ssrFetchMock).toHaveBeenCalledWith('/settings/access', {
      headers: {
        'X-Settings-Access': '1',
      },
    });
    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected settings access success');
    }

    expect(result.data.sectionKey).toBe('access');
    expect(result.data.acknowledgeLabel).toBe('Acknowledge & Mark Reviewed');
  });

  it('loadModulesHub calls the real Modules endpoint with SSR headers', async () => {
    ssrFetchMock.mockResolvedValueOnce(jsonResponse(makeModules()));

    const result = await loadModulesHub();

    expect(ssrFetchMock).toHaveBeenCalledWith('/settings/modules', {
      headers: {
        'X-Settings-Modules': '1',
      },
    });
    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected settings modules success');
    }

    expect(result.data.cards[0]?.key).toBe('personal');
  });

  it('loadPersonalSettings calls the real Personal endpoint with SSR headers', async () => {
    ssrFetchMock.mockResolvedValueOnce(jsonResponse(makePersonal()));

    const result = await loadPersonalSettings();

    expect(ssrFetchMock).toHaveBeenCalledWith('/settings/modules/personal', {
      headers: {
        'X-Settings-Personal': '1',
      },
    });
    expect(result.ok).toBe(true);

    if (!result.ok) {
      throw new Error('Expected settings personal success');
    }

    expect(result.data.familyReview.families[0]?.familyKey).toBe('identity');
  });
});
