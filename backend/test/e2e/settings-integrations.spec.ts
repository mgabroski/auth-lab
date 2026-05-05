import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { INTEGRATION_CATALOG } from '../../src/modules/control-plane/accounts/cp-accounts.catalog';
import type { SaveCpIntegrationsInput } from '../../src/modules/control-plane/accounts/cp-accounts.schemas';
import type { IntegrationsSettingsResponse } from '../../src/modules/settings/settings.types';
import { up as upSettingsFoundationMigration } from '../../src/shared/db/migrations/0017_settings_foundation';
import { up as upSettingsAccountMigration } from '../../src/shared/db/migrations/0018_settings_account';
import { buildTestApp } from '../helpers/build-test-app';
import { createAdminSession } from '../helpers/create-admin-session';

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function buildIntegrationsPayload(params?: {
  googleAllowed?: boolean;
  microsoftAllowed?: boolean;
}): SaveCpIntegrationsInput {
  return {
    integrations: INTEGRATION_CATALOG.map((integration) => ({
      integrationKey: integration.integrationKey,
      isAllowed:
        integration.integrationKey === 'integration.sso.google'
          ? (params?.googleAllowed ?? integration.defaultAllowed)
          : integration.integrationKey === 'integration.sso.microsoft'
            ? (params?.microsoftAllowed ?? integration.defaultAllowed)
            : integration.defaultAllowed,
      capabilities: integration.capabilities.map((capability) => ({
        capabilityKey: capability.capabilityKey,
        isAllowed: capability.defaultAllowed,
      })),
    })),
  };
}

async function provisionActiveCpTenant(params: {
  app: Awaited<ReturnType<typeof buildTestApp>>['app'];
  deps: Awaited<ReturnType<typeof buildTestApp>>['deps'];
  accountKey: string;
  googleLoginEnabled?: boolean;
  microsoftLoginEnabled?: boolean;
  googleIntegrationAllowed?: boolean;
  microsoftIntegrationAllowed?: boolean;
}): Promise<{ tenantId: string; tenantKey: string }> {
  const createRes = await params.app.inject({
    method: 'POST',
    url: '/cp/accounts',
    payload: {
      accountName: `Settings Integrations ${params.accountKey}`,
      accountKey: params.accountKey,
    },
  });
  expect(createRes.statusCode).toBe(201);

  const accountSettingsRes = await params.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${params.accountKey}/account-settings`,
    payload: {
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
    payload: buildIntegrationsPayload({
      googleAllowed: params.googleIntegrationAllowed ?? false,
      microsoftAllowed: params.microsoftIntegrationAllowed ?? false,
    }),
  });
  expect(integrationsRes.statusCode).toBe(200);

  const accessRes = await params.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${params.accountKey}/access`,
    payload: {
      loginMethods: {
        password: true,
        google: params.googleLoginEnabled ?? false,
        microsoft: params.microsoftLoginEnabled ?? false,
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

describe('settings integrations phase 9 surface', () => {
  it('returns truthful SSO/deferred integration data without fake connected flows', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-integrations-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await provisionActiveCpTenant({
        app,
        deps,
        accountKey,
        googleLoginEnabled: true,
        googleIntegrationAllowed: true,
        microsoftLoginEnabled: false,
        microsoftIntegrationAllowed: false,
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
        url: '/settings/integrations',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<IntegrationsSettingsResponse>(res);

      expect(body.sectionKey).toBe('integrations');
      expect(body.status).toBe('NOT_STARTED');
      expect(body.ssoIntegrations).toHaveLength(2);

      const google = body.ssoIntegrations.find(
        (integration) => integration.integrationKey === 'integration.sso.google',
      );
      expect(google).toBeDefined();
      expect(google?.visible).toBe(true);
      expect(google?.cpAllowed).toBe(true);
      expect(google?.loginMethodEnabled).toBe(true);
      expect(google?.displayStatus).toBe('BLOCKED');
      expect(google?.runtimeReadiness.status).toBe('SNAPSHOT_UNAVAILABLE');
      expect(google?.warnings.join(' ')).toContain(
        'Settings GET routes do not make live provider calls',
      );
      expect(google?.credentialEntryAvailable).toBe(false);
      expect(google?.connectionFlowAvailable).toBe(false);
      expect(google?.tenantConfigurationAvailable).toBe(false);

      const microsoft = body.ssoIntegrations.find(
        (integration) => integration.integrationKey === 'integration.sso.microsoft',
      );
      expect(microsoft).toBeDefined();
      expect(microsoft?.visible).toBe(false);
      expect(microsoft?.displayStatus).toBe('HIDDEN');

      expect(
        body.deferredIntegrations.map((integration) => integration.integrationKey).sort(),
      ).toEqual([
        'integration.adp',
        'integration.hint',
        'integration.istream',
        'integration.stripe',
      ]);
      expect(body.deferredIntegrations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            integrationKey: 'integration.adp',
            treatment: 'DEFERRED',
            credentialEntryAvailable: false,
            mappingEditorAvailable: false,
            syncEngineAvailable: false,
          }),
          expect.objectContaining({
            integrationKey: 'integration.stripe',
            treatment: 'DEFERRED',
            credentialEntryAvailable: false,
            connectionFlowAvailable: false,
          }),
        ]),
      );
      expect(body.marketplace).toEqual(
        expect.objectContaining({
          integrationKey: 'integration.marketplace',
          treatment: 'PLACEHOLDER_ONLY',
          visible: false,
        }),
      );

      const serialized = JSON.stringify(body);
      expect(serialized).not.toContain('Connected');
      expect(serialized).not.toContain('Reconnect');
      expect(serialized).not.toContain('Connect now');
    } finally {
      await close();
    }
  });

  it('distinguishes ready, not-in-use, and hidden SSO integration states', async () => {
    const { app, deps, close, reset } = await buildTestApp({
      sso: {
        stateEncryptionKeyBase64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        redirectBaseUrl: 'http://localhost:3000',
        googleClientId: 'test-google-client-id',
        googleClientSecret: 'test-google-client-secret',
        microsoftClientId: 'test-microsoft-client-id',
        microsoftClientSecret: 'test-microsoft-client-secret',
        localOidc: {
          issuerUrl: 'http://localhost:9998',
          clientId: 'test-local-oidc-client',
        },
      },
    });
    const accountKey = `settings-integrations-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await provisionActiveCpTenant({
        app,
        deps,
        accountKey,
        googleLoginEnabled: true,
        googleIntegrationAllowed: true,
        microsoftLoginEnabled: false,
        microsoftIntegrationAllowed: true,
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
        url: '/settings/integrations',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<IntegrationsSettingsResponse>(res);
      const google = body.ssoIntegrations.find(
        (integration) => integration.integrationKey === 'integration.sso.google',
      );
      const microsoft = body.ssoIntegrations.find(
        (integration) => integration.integrationKey === 'integration.sso.microsoft',
      );

      expect(google?.visible).toBe(true);
      expect(google?.displayStatus).toBe('READY');
      expect(google?.runtimeReadiness.status).toBe('READY');
      expect(google?.warnings).toEqual([]);

      expect(microsoft?.visible).toBe(true);
      expect(microsoft?.displayStatus).toBe('NOT_IN_USE');
      expect(microsoft?.loginMethodEnabled).toBe(false);
      expect(microsoft?.credentialEntryAvailable).toBe(false);
    } finally {
      await close();
    }
  });

  it('keeps hidden integrations invisible and rejects non-admin access', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-integrations-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await provisionActiveCpTenant({
        app,
        deps,
        accountKey,
        googleLoginEnabled: false,
        googleIntegrationAllowed: false,
        microsoftLoginEnabled: false,
        microsoftIntegrationAllowed: false,
      });

      const unauthenticatedRes = await app.inject({
        method: 'GET',
        url: '/settings/integrations',
        headers: {
          host: hostForTenant(tenant.tenantKey),
        },
      });
      expect(unauthenticatedRes.statusCode).toBe(401);

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
        url: '/settings/integrations',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<IntegrationsSettingsResponse>(res);
      expect(
        body.ssoIntegrations.every((integration) => integration.displayStatus === 'HIDDEN'),
      ).toBe(true);
      expect(body.ssoIntegrations.every((integration) => integration.visible === false)).toBe(true);
    } finally {
      await close();
    }
  });
});
