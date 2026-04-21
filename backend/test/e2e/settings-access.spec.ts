import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  EDITABLE_PERSONAL_FIELD_CATALOG,
  INTEGRATION_CATALOG,
  PERSONAL_FAMILY_DEFAULTS,
} from '../../src/modules/control-plane/accounts/cp-accounts.catalog';
import type {
  SaveCpIntegrationsInput,
  SaveCpPersonalInput,
} from '../../src/modules/control-plane/accounts/cp-accounts.schemas';
import type {
  AccessSettingsResponse,
  SettingsMutationResponse,
} from '../../src/modules/settings/settings.types';
import { up as upSettingsFoundationMigration } from '../../src/shared/db/migrations/0017_settings_foundation';
import { up as upSettingsAccountMigration } from '../../src/shared/db/migrations/0018_settings_account';
import { buildTestApp } from '../helpers/build-test-app';
import { createAdminSession } from '../helpers/create-admin-session';

type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
  };
};

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

function buildValidPersonalPayload(): SaveCpPersonalInput {
  return {
    families: PERSONAL_FAMILY_DEFAULTS.map((family) => ({
      familyKey: family.familyKey,
      isAllowed: family.defaultAllowed,
    })),
    fields: EDITABLE_PERSONAL_FIELD_CATALOG.map((field) => ({
      fieldKey: field.fieldKey,
      isAllowed: field.defaultAllowed,
      defaultSelected: field.defaultSelected,
    })),
  };
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
  personalEnabled: boolean;
  googleLoginEnabled?: boolean;
  googleIntegrationAllowed?: boolean;
}): Promise<{ tenantId: string; tenantKey: string }> {
  const createRes = await params.app.inject({
    method: 'POST',
    url: '/cp/accounts',
    payload: {
      accountName: `Settings Access ${params.accountKey}`,
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
        personal: params.personalEnabled,
        documents: false,
        benefits: false,
        payments: false,
      },
    },
  });
  expect(modulesRes.statusCode).toBe(200);

  if (params.personalEnabled) {
    const personalRes = await params.app.inject({
      method: 'PUT',
      url: `/cp/accounts/${params.accountKey}/modules/personal`,
      payload: buildValidPersonalPayload(),
    });
    expect(personalRes.statusCode).toBe(200);
  }

  const integrationsRes = await params.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${params.accountKey}/integrations`,
    payload: buildIntegrationsPayload({
      googleAllowed: params.googleIntegrationAllowed ?? false,
      microsoftAllowed: false,
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

describe('settings access phase 4 surface', () => {
  it('returns the real Access DTO with read-only groups and operational warnings', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-access-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await provisionActiveCpTenant({
        app,
        deps,
        accountKey,
        personalEnabled: true,
        googleLoginEnabled: true,
        googleIntegrationAllowed: true,
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
        url: '/settings/access',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<AccessSettingsResponse>(res);

      expect(body.sectionKey).toBe('access');
      expect(body.status).toBe('NOT_STARTED');
      expect(body.version).toBe(1);
      expect(body.canAcknowledge).toBe(true);
      expect(body.acknowledgeLabel).toBe('Acknowledge & Mark Reviewed');
      expect(body.groups.map((group) => group.key)).toEqual([
        'loginMethods',
        'mfaPolicy',
        'signupPolicy',
      ]);

      const loginRows = body.groups[0]?.rows ?? [];
      expect(loginRows.map((row) => row.label)).toEqual(['Username & Password', 'Google SSO']);
      expect(loginRows.every((row) => row.readOnly)).toBe(true);
      expect(loginRows[1]?.status).toBe('WARNING');
      expect(loginRows[1]?.resolutionHref).toBe('/admin/settings/integrations');
      expect(body.warnings.join(' ')).toContain('runtime readiness is unavailable');
      expect(body.blockers).toEqual([]);
      expect(body.nextAction?.href).toBe('/admin/settings/access');
    } finally {
      await close();
    }
  });

  it('acknowledges Access explicitly, updates only its own boundary, and recomputes aggregate truth', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-ack-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await provisionActiveCpTenant({
        app,
        deps,
        accountKey,
        personalEnabled: true,
        googleLoginEnabled: false,
        googleIntegrationAllowed: false,
      });

      const admin = await createAdminSession({
        app,
        deps,
        tenantId: tenant.tenantId,
        tenantKey: tenant.tenantKey,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const before = await deps.settings.foundationRepo.getStateBundle(tenant.tenantId);
      expect(before?.sections.access.status).toBe('NOT_STARTED');
      expect(before?.sections.account.status).toBe('NOT_STARTED');
      expect(before?.sections.personal.status).toBe('NOT_STARTED');
      expect(before?.aggregate.overallStatus).toBe('NOT_STARTED');

      const accessRes = await app.inject({
        method: 'GET',
        url: '/settings/access',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });
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
      const mutation = readJson<SettingsMutationResponse>(ackRes);
      expect(mutation.section).toEqual({
        key: 'access',
        status: 'COMPLETE',
        version: 2,
        cpRevision: access.cpRevision,
      });
      expect(mutation.aggregate.status).toBe('IN_PROGRESS');
      expect(mutation.aggregate.nextAction?.href).toBe('/admin/settings/modules/personal');

      const after = await deps.settings.foundationRepo.getStateBundle(tenant.tenantId);
      expect(after?.sections.access.status).toBe('COMPLETE');
      expect(after?.sections.access.lastReviewedByUserId).toBe(admin.userId);
      expect(after?.sections.account.version).toBe(before?.sections.account.version);
      expect(after?.sections.account.status).toBe(before?.sections.account.status);
      expect(after?.sections.personal.version).toBe(before?.sections.personal.version);
      expect(after?.sections.personal.status).toBe(before?.sections.personal.status);
      expect(after?.sections.integrations.version).toBe(before?.sections.integrations.version);
      expect(after?.aggregate.overallStatus).toBe('IN_PROGRESS');

      const audits = await deps.db
        .selectFrom('audit_events')
        .select(['action', 'metadata'])
        .where('action', 'like', 'settings.access.%')
        .orderBy('created_at asc')
        .execute();

      expect(audits.map((audit) => audit.action)).toEqual(['settings.access.acknowledged']);
      const successMetadata = audits[0]?.metadata as Record<string, unknown>;
      expect(successMetadata.tenantId).toBe(tenant.tenantId);
      expect(successMetadata.status).toBe('COMPLETE');
      expect(successMetadata.aggregateStatus).toBe('IN_PROGRESS');
    } finally {
      await close();
    }
  });

  it('fails closed when a CP mismatch exists and writes a durable failure audit', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-block-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await provisionActiveCpTenant({
        app,
        deps,
        accountKey,
        personalEnabled: false,
        googleLoginEnabled: true,
        googleIntegrationAllowed: true,
      });

      const cpAccount = await deps.db
        .selectFrom('cp_accounts')
        .select('id')
        .where('account_key', '=', accountKey)
        .executeTakeFirstOrThrow();

      await deps.db
        .updateTable('cp_integration_config')
        .set({ is_allowed: false })
        .where('account_id', '=', cpAccount.id)
        .where('integration_key', '=', 'integration.sso.google')
        .execute();

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
      const access = readJson<AccessSettingsResponse>(accessRes);
      expect(access.canAcknowledge).toBe(false);
      expect(access.blockers.join(' ')).toContain('fails closed');

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

      expect(ackRes.statusCode).toBe(409);
      const error = readJson<ErrorResponseBody>(ackRes);
      expect(error.error.code).toBe('CONFLICT');
      expect(error.error.message).toBe(
        'Access & Security cannot be acknowledged while platform-managed blockers remain unresolved.',
      );

      const audits = await deps.db
        .selectFrom('audit_events')
        .select(['action', 'metadata'])
        .where('action', 'like', 'settings.access.%')
        .orderBy('created_at asc')
        .execute();

      expect(audits.map((audit) => audit.action)).toEqual(['settings.access.acknowledge.failed']);
      const failureMetadata = audits[0]?.metadata as Record<string, unknown>;
      expect(failureMetadata.tenantId).toBe(tenant.tenantId);
      expect(failureMetadata.errorCode).toBe('CONFLICT');
      expect(failureMetadata.expectedVersion).toBe(access.version);
      expect(failureMetadata.expectedCpRevision).toBe(access.cpRevision);
    } finally {
      await close();
    }
  });

  it('returns honest conflict responses for stale version and stale cpRevision submissions', async () => {
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
        personalEnabled: false,
        googleLoginEnabled: false,
        googleIntegrationAllowed: false,
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
      const access = readJson<AccessSettingsResponse>(accessRes);

      const firstAckRes = await app.inject({
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
      expect(firstAckRes.statusCode).toBe(200);

      const staleVersionRes = await app.inject({
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
      expect(staleVersionRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(staleVersionRes).error.message).toBe(
        'Access settings changed while you were reviewing them. Refresh the page and try again.',
      );

      const freshAccessRes = await app.inject({
        method: 'GET',
        url: '/settings/access',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
      });
      const freshAccess = readJson<AccessSettingsResponse>(freshAccessRes);

      const cpChangeRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: {
          loginMethods: {
            password: true,
            google: false,
            microsoft: false,
          },
          mfaPolicy: {
            adminRequired: true,
            memberRequired: true,
          },
          signupPolicy: {
            publicSignup: false,
            adminInvitationsAllowed: true,
            allowedDomains: [],
          },
        },
      });
      expect(cpChangeRes.statusCode).toBe(200);

      const staleCpRevisionRes = await app.inject({
        method: 'POST',
        url: '/settings/access/acknowledge',
        headers: {
          host: hostForTenant(tenant.tenantKey),
          cookie: admin.cookie,
        },
        payload: {
          expectedVersion: freshAccess.version,
          expectedCpRevision: freshAccess.cpRevision,
        },
      });
      expect(staleCpRevisionRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(staleCpRevisionRes).error.message).toBe(
        'Access settings changed after this page was loaded. Refresh and review the latest platform-managed access rules before acknowledging.',
      );
    } finally {
      await close();
    }
  });
});
