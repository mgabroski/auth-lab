import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';
import { createAdminSession } from '../helpers/create-admin-session';
import { up as upSettingsFoundationMigration } from '../../src/shared/db/migrations/0017_settings_foundation';
import { up as upSettingsAccountMigration } from '../../src/shared/db/migrations/0018_settings_account';
import type {
  AccessSettingsResponse,
  AccountSettingsResponse,
  SettingsBootstrapResponse,
  SettingsMutationResponse,
} from '../../src/modules/settings/settings.types';

type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
  };
};

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

async function provisionActiveCpTenant(params: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  deps: Awaited<ReturnType<typeof buildTestApp>>['deps'];
  accountKey: string;
  accountSettingsPayload?: {
    branding: {
      logo: boolean;
      menuColor: boolean;
      fontColor: boolean;
      welcomeMessage: boolean;
    };
    organizationStructure: {
      employers: boolean;
      locations: boolean;
    };
    companyCalendar: {
      allowed: boolean;
    };
  };
}): Promise<{ tenantId: string; tenantKey: string }> {
  const createRes = await params.app.inject({
    method: 'POST',
    url: '/cp/accounts',
    payload: {
      accountName: `Settings Account ${params.accountKey}`,
      accountKey: params.accountKey,
    },
  });
  expect(createRes.statusCode).toBe(201);

  const accountSettingsRes = await params.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${params.accountKey}/account-settings`,
    payload: params.accountSettingsPayload ?? {
      branding: {
        logo: true,
        menuColor: true,
        fontColor: true,
        welcomeMessage: true,
      },
      organizationStructure: {
        employers: true,
        locations: true,
      },
      companyCalendar: {
        allowed: true,
      },
    },
  });
  expect(accountSettingsRes.statusCode).toBe(200);

  const modulesRes = await params.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${params.accountKey}/modules`,
    payload: {
      modules: {
        personal: false,
        documents: false,
        benefits: false,
        payments: false,
      },
    },
  });
  expect(modulesRes.statusCode).toBe(200);

  const integrationsRes = await params.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${params.accountKey}/integrations`,
    payload: {
      integrations: [
        { integrationKey: 'integration.adp', isAllowed: false, capabilities: [] },
        { integrationKey: 'integration.hint', isAllowed: false, capabilities: [] },
        { integrationKey: 'integration.istream', isAllowed: false, capabilities: [] },
        { integrationKey: 'integration.stripe', isAllowed: false, capabilities: [] },
        { integrationKey: 'integration.sso.google', isAllowed: false, capabilities: [] },
        { integrationKey: 'integration.sso.microsoft', isAllowed: false, capabilities: [] },
      ],
    },
  });
  expect(integrationsRes.statusCode).toBe(200);

  const accessRes = await params.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${params.accountKey}/access`,
    payload: {
      loginMethods: {
        password: true,
        google: false,
        microsoft: false,
      },
      mfaPolicy: {
        adminRequired: true,
        memberRequired: false,
      },
      signupPolicy: {
        publicSignup: false,
        adminInvitationsAllowed: true,
        allowedDomains: [],
      },
    },
  });
  expect(accessRes.statusCode).toBe(200);

  const publishRes = await params.app.inject({
    method: 'POST',
    url: `/cp/accounts/${params.accountKey}/publish`,
    payload: {
      targetStatus: 'Active',
    },
  });
  expect(publishRes.statusCode).toBe(200);

  const tenant = await params.deps.db
    .selectFrom('tenants')
    .select(['id', 'key'])
    .where('key', '=', params.accountKey)
    .executeTakeFirstOrThrow();

  return {
    tenantId: tenant.id,
    tenantKey: tenant.key,
  };
}

describe('settings account surface', () => {
  it('returns the real Account DTO, saves Branding, and writes account audit coverage', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-account-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await provisionActiveCpTenant({
        app,
        deps,
        accountKey,
      });

      const admin = await createAdminSession({
        app,
        deps,
        tenantId: tenant.tenantId,
        tenantKey: tenant.tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const beforeRes = await app.inject({
        method: 'GET',
        url: '/settings/account',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });

      expect(beforeRes.statusCode).toBe(200);
      const before = readJson<AccountSettingsResponse>(beforeRes);

      expect(before.sectionKey).toBe('account');
      expect(before.status).toBe('NOT_STARTED');
      expect(before.cards.map((card) => card.key)).toEqual([
        'branding',
        'orgStructure',
        'calendar',
      ]);
      expect(before.cards.every((card) => card.version === 1)).toBe(true);

      const brandingCard = before.cards.find((card) => card.key === 'branding');
      expect(brandingCard).toBeDefined();
      expect(brandingCard?.status).toBe('NOT_STARTED');

      const mutationRes = await app.inject({
        method: 'PUT',
        url: '/settings/account/branding',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
        payload: {
          expectedVersion: brandingCard?.version,
          expectedCpRevision: brandingCard?.cpRevision,
          values: {
            logoUrl: 'https://cdn.example.com/logo.svg',
            menuColor: '#0f172a',
            fontColor: '#ffffff',
            welcomeMessage: 'Welcome to the workspace',
          },
        },
      });

      expect(mutationRes.statusCode).toBe(200);
      const mutation = readJson<SettingsMutationResponse>(mutationRes);
      expect(mutation.section.key).toBe('account');
      expect(mutation.section.status).toBe('IN_PROGRESS');
      expect(mutation.card).toEqual({
        key: 'branding',
        status: 'COMPLETE',
        version: 2,
        cpRevision: brandingCard?.cpRevision,
      });
      expect(mutation.aggregate.status).toBe('IN_PROGRESS');
      expect(mutation.aggregate.nextAction?.href).toBe('/admin/settings/access');

      const afterRes = await app.inject({
        method: 'GET',
        url: '/settings/account',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });
      expect(afterRes.statusCode).toBe(200);
      const after = readJson<AccountSettingsResponse>(afterRes);
      const updatedBranding = after.cards.find((card) => card.key === 'branding');
      expect(updatedBranding).toBeDefined();
      expect(updatedBranding?.status).toBe('COMPLETE');
      expect(updatedBranding?.version).toBe(2);
      if (updatedBranding?.key !== 'branding') {
        throw new Error('Expected branding card');
      }
      expect(updatedBranding.values).toEqual({
        logoUrl: 'https://cdn.example.com/logo.svg',
        menuColor: '#0f172a',
        fontColor: '#ffffff',
        welcomeMessage: 'Welcome to the workspace',
      });

      const state = await deps.settings.foundationRepo.getStateBundle(tenant.tenantId);
      expect(state?.sections.account.status).toBe('IN_PROGRESS');
      expect(state?.sections.access.status).toBe('NOT_STARTED');
      expect(state?.aggregate.overallStatus).toBe('IN_PROGRESS');

      const audits = await deps.db
        .selectFrom('audit_events')
        .select(['action', 'metadata'])
        .where('action', 'like', 'settings.account.%')
        .orderBy('created_at asc')
        .execute();

      expect(audits.map((audit) => audit.action)).toEqual(['settings.account.branding.saved']);
      const successMetadata = audits[0]?.metadata as Record<string, unknown>;
      expect(successMetadata.cardKey).toBe('branding');
      expect(successMetadata.cardVersion).toBe(2);
      expect(successMetadata.sectionStatus).toBe('IN_PROGRESS');
      expect(successMetadata.aggregateStatus).toBe('IN_PROGRESS');
    } finally {
      await close();
    }
  });

  it('returns version and cpRevision conflicts per card, but accepts a stale cpRevision when the payload still fits current allowance truth', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-conflict-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await provisionActiveCpTenant({
        app,
        deps,
        accountKey,
      });

      const admin = await createAdminSession({
        app,
        deps,
        tenantId: tenant.tenantId,
        tenantKey: tenant.tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const initialRes = await app.inject({
        method: 'GET',
        url: '/settings/account',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });
      expect(initialRes.statusCode).toBe(200);
      const initial = readJson<AccountSettingsResponse>(initialRes);
      const branding = initial.cards.find((card) => card.key === 'branding');
      if (!branding || branding.key !== 'branding') {
        throw new Error('Expected Branding card');
      }

      const firstSaveRes = await app.inject({
        method: 'PUT',
        url: '/settings/account/branding',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
        payload: {
          expectedVersion: branding.version,
          expectedCpRevision: branding.cpRevision,
          values: {
            logoUrl: 'https://cdn.example.com/logo.svg',
            menuColor: null,
            fontColor: null,
            welcomeMessage: null,
          },
        },
      });
      expect(firstSaveRes.statusCode).toBe(200);

      const staleVersionRes = await app.inject({
        method: 'PUT',
        url: '/settings/account/branding',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
        payload: {
          expectedVersion: branding.version,
          expectedCpRevision: branding.cpRevision,
          values: {
            logoUrl: 'https://cdn.example.com/logo-2.svg',
            menuColor: null,
            fontColor: null,
            welcomeMessage: null,
          },
        },
      });
      expect(staleVersionRes.statusCode).toBe(409);
      const staleVersion = readJson<ErrorResponseBody>(staleVersionRes);
      expect(staleVersion.error.message).toContain('Branding changed while you were editing it');

      const cpChangedRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/account-settings`,
        payload: {
          branding: {
            logo: false,
            menuColor: true,
            fontColor: true,
            welcomeMessage: true,
          },
          organizationStructure: {
            employers: true,
            locations: true,
          },
          companyCalendar: {
            allowed: true,
          },
        },
      });
      expect(cpChangedRes.statusCode).toBe(200);

      const accountRow = await deps.settings.accountRepo.getByTenantId(tenant.tenantId);
      expect(accountRow?.branding.appliedCpRevision).toBe(branding.cpRevision + 1);
      expect(accountRow?.branding.version).toBe(2);

      const staleCpInvalidPayloadRes = await app.inject({
        method: 'PUT',
        url: '/settings/account/branding',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
        payload: {
          expectedVersion: 2,
          expectedCpRevision: branding.cpRevision,
          values: {
            logoUrl: 'https://cdn.example.com/stale.svg',
            menuColor: '#111827',
            fontColor: '#ffffff',
            welcomeMessage: null,
          },
        },
      });
      expect(staleCpInvalidPayloadRes.statusCode).toBe(409);
      const staleCpInvalid = readJson<ErrorResponseBody>(staleCpInvalidPayloadRes);
      expect(staleCpInvalid.error.message).toContain('Branding changed after this page was loaded');

      const staleCpButValidPayloadRes = await app.inject({
        method: 'PUT',
        url: '/settings/account/branding',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
        payload: {
          expectedVersion: 2,
          expectedCpRevision: branding.cpRevision,
          values: {
            logoUrl: null,
            menuColor: '#111827',
            fontColor: '#ffffff',
            welcomeMessage: 'Still valid under the latest allowance',
          },
        },
      });
      expect(staleCpButValidPayloadRes.statusCode).toBe(200);
      const staleAccepted = readJson<SettingsMutationResponse>(staleCpButValidPayloadRes);
      expect(staleAccepted.card).toEqual({
        key: 'branding',
        status: 'COMPLETE',
        version: 3,
        cpRevision: branding.cpRevision + 1,
      });

      const audits = await deps.db
        .selectFrom('audit_events')
        .select(['action', 'metadata'])
        .where('action', 'like', 'settings.account.branding%')
        .orderBy('created_at asc')
        .execute();

      expect(audits.map((audit) => audit.action)).toEqual([
        'settings.account.branding.saved',
        'settings.account.branding.save.failed',
        'settings.account.branding.save.failed',
        'settings.account.branding.saved',
      ]);
    } finally {
      await close();
    }
  });

  it('keeps banner truth stable when Account saves occur after required setup is complete', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-banner-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await provisionActiveCpTenant({
        app,
        deps,
        accountKey,
      });

      const admin = await createAdminSession({
        app,
        deps,
        tenantId: tenant.tenantId,
        tenantKey: tenant.tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const accessRes = await app.inject({
        method: 'GET',
        url: '/settings/access',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });
      expect(accessRes.statusCode).toBe(200);
      const access = readJson<AccessSettingsResponse>(accessRes);

      const ackRes = await app.inject({
        method: 'POST',
        url: '/settings/access/acknowledge',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
        payload: {
          expectedVersion: access.version,
          expectedCpRevision: access.cpRevision,
        },
      });
      expect(ackRes.statusCode).toBe(200);
      const ackMutation = readJson<SettingsMutationResponse>(ackRes);
      expect(ackMutation.aggregate.status).toBe('COMPLETE');

      const bootstrapBeforeRes = await app.inject({
        method: 'GET',
        url: '/settings/bootstrap',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });
      expect(bootstrapBeforeRes.statusCode).toBe(200);
      const bootstrapBefore = readJson<SettingsBootstrapResponse>(bootstrapBeforeRes);
      expect(bootstrapBefore).toEqual({
        overallStatus: 'COMPLETE',
        showSetupBanner: false,
        nextAction: null,
      });

      const accountRes = await app.inject({
        method: 'GET',
        url: '/settings/account',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });
      expect(accountRes.statusCode).toBe(200);
      const account = readJson<AccountSettingsResponse>(accountRes);
      const calendar = account.cards.find((card) => card.key === 'calendar');
      if (!calendar || calendar.key !== 'calendar') {
        throw new Error('Expected Company Calendar card');
      }

      const saveCalendarRes = await app.inject({
        method: 'PUT',
        url: '/settings/account/calendar',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
        payload: {
          expectedVersion: calendar.version,
          expectedCpRevision: calendar.cpRevision,
          values: {
            observedDates: ['2026-01-01', '2026-12-25'],
          },
        },
      });
      expect(saveCalendarRes.statusCode).toBe(200);
      const saveCalendar = readJson<SettingsMutationResponse>(saveCalendarRes);
      expect(saveCalendar.aggregate.status).toBe('COMPLETE');
      expect(saveCalendar.aggregate.nextAction).toBeNull();

      const bootstrapAfterRes = await app.inject({
        method: 'GET',
        url: '/settings/bootstrap',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });
      expect(bootstrapAfterRes.statusCode).toBe(200);
      const bootstrapAfter = readJson<SettingsBootstrapResponse>(bootstrapAfterRes);
      expect(bootstrapAfter).toEqual({
        overallStatus: 'COMPLETE',
        showSetupBanner: false,
        nextAction: null,
      });
    } finally {
      await close();
    }
  });

  it('treats Account as hidden when CP disallows every Account card', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-hidden-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await provisionActiveCpTenant({
        app,
        deps,
        accountKey,
        accountSettingsPayload: {
          branding: {
            logo: false,
            menuColor: false,
            fontColor: false,
            welcomeMessage: false,
          },
          organizationStructure: {
            employers: false,
            locations: false,
          },
          companyCalendar: {
            allowed: false,
          },
        },
      });

      const admin = await createAdminSession({
        app,
        deps,
        tenantId: tenant.tenantId,
        tenantKey: tenant.tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/settings/account',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });

      expect(res.statusCode).toBe(404);
      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toBe('Account Settings is not available for this workspace.');

      const overviewRes = await app.inject({
        method: 'GET',
        url: '/settings/overview',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });
      expect(overviewRes.statusCode).toBe(200);
      const overview = readJson<{ cards: Array<{ key: string }> }>(overviewRes);
      expect(overview.cards.some((card) => card.key === 'account')).toBe(false);
    } finally {
      await close();
    }
  });
});
