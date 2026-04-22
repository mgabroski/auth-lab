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
import { buildTestApp } from '../helpers/build-test-app';
import { up as upSettingsFoundationMigration } from '../../src/shared/db/migrations/0017_settings_foundation';
import { up as upSettingsAccountMigration } from '../../src/shared/db/migrations/0018_settings_account';
import { createAdminSession } from '../helpers/create-admin-session';
import type {
  ModulesHubResponse,
  PersonalSettingsResponse,
} from '../../src/modules/settings/settings.types';

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
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

function buildSelectivePersonalPayload(params: { allowedFamilies: string[] }): SaveCpPersonalInput {
  const allowedFamilies = new Set(params.allowedFamilies);

  return {
    families: PERSONAL_FAMILY_DEFAULTS.map((family) => ({
      familyKey: family.familyKey,
      isAllowed: allowedFamilies.has(family.familyKey),
    })),
    fields: EDITABLE_PERSONAL_FIELD_CATALOG.map((field) => {
      const familyAllowed = allowedFamilies.has(field.familyKey);

      return {
        fieldKey: field.fieldKey,
        isAllowed: familyAllowed ? field.defaultAllowed : false,
        defaultSelected: familyAllowed ? field.defaultSelected : false,
      };
    }),
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

describe('settings modules hub and Personal field foundations', () => {
  it('returns a truthful modules hub with one live Personal card and placeholder-only future modules', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      expect(
        (
          await app.inject({
            method: 'POST',
            url: '/cp/accounts',
            payload: {
              accountName: 'Settings Modules Tenant',
              accountKey,
            },
          })
        ).statusCode,
      ).toBe(201);

      expect(
        (
          await app.inject({
            method: 'PUT',
            url: `/cp/accounts/${accountKey}/access`,
            payload: {
              loginMethods: { password: true, google: false, microsoft: false },
              mfaPolicy: { adminRequired: true, memberRequired: false },
              signupPolicy: {
                publicSignup: false,
                adminInvitationsAllowed: true,
                allowedDomains: [],
              },
            },
          })
        ).statusCode,
      ).toBe(200);

      expect(
        (
          await app.inject({
            method: 'PUT',
            url: `/cp/accounts/${accountKey}/account-settings`,
            payload: {
              branding: { logo: true, menuColor: true, fontColor: true, welcomeMessage: true },
              organizationStructure: { employers: true, locations: true },
              companyCalendar: { allowed: true },
            },
          })
        ).statusCode,
      ).toBe(200);

      expect(
        (
          await app.inject({
            method: 'PUT',
            url: `/cp/accounts/${accountKey}/modules`,
            payload: {
              modules: {
                personal: true,
                documents: true,
                benefits: false,
                payments: true,
              },
            },
          })
        ).statusCode,
      ).toBe(200);

      expect(
        (
          await app.inject({
            method: 'PUT',
            url: `/cp/accounts/${accountKey}/modules/personal`,
            payload: buildValidPersonalPayload(),
          })
        ).statusCode,
      ).toBe(200);

      expect(
        (
          await app.inject({
            method: 'PUT',
            url: `/cp/accounts/${accountKey}/integrations`,
            payload: buildIntegrationsPayload({
              googleAllowed: false,
              microsoftAllowed: false,
            }),
          })
        ).statusCode,
      ).toBe(200);

      expect(
        (
          await app.inject({
            method: 'POST',
            url: `/cp/accounts/${accountKey}/publish`,
            payload: { targetStatus: 'Active' },
          })
        ).statusCode,
      ).toBe(200);

      const tenant = await deps.db
        .selectFrom('tenants')
        .select(['id', 'key'])
        .where('key', '=', accountKey)
        .executeTakeFirstOrThrow();

      const admin = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const modulesRes = await app.inject({
        method: 'GET',
        url: '/settings/modules',
        headers: {
          host: hostForTenant(tenant.key),
          cookie: admin.cookie,
        },
      });

      expect(modulesRes.statusCode).toBe(200);

      const modules = readJson<ModulesHubResponse>(modulesRes);
      expect(modules.visibleModuleKeys).toEqual(['personal', 'documents', 'payments']);
      expect(modules.cards).toEqual([
        expect.objectContaining({
          key: 'personal',
          classification: 'LIVE',
          href: '/admin/settings/modules/personal',
          status: 'NOT_STARTED',
        }),
        expect.objectContaining({
          key: 'documents',
          classification: 'PLACEHOLDER',
          href: null,
          status: 'PLACEHOLDER',
        }),
        expect.objectContaining({
          key: 'payments',
          classification: 'PLACEHOLDER',
          href: null,
          status: 'PLACEHOLDER',
        }),
      ]);
    } finally {
      await close();
    }
  });

  it('returns the Personal foundation DTO and hides Personal when the module is not allowed', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const enabledKey = `enabled-${randomUUID().slice(0, 8)}`;
    const disabledKey = `disabled-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      for (const accountKey of [enabledKey, disabledKey]) {
        expect(
          (
            await app.inject({
              method: 'POST',
              url: '/cp/accounts',
              payload: { accountName: `Tenant ${accountKey}`, accountKey },
            })
          ).statusCode,
        ).toBe(201);

        expect(
          (
            await app.inject({
              method: 'PUT',
              url: `/cp/accounts/${accountKey}/access`,
              payload: {
                loginMethods: { password: true, google: false, microsoft: false },
                mfaPolicy: { adminRequired: true, memberRequired: false },
                signupPolicy: {
                  publicSignup: false,
                  adminInvitationsAllowed: true,
                  allowedDomains: [],
                },
              },
            })
          ).statusCode,
        ).toBe(200);

        expect(
          (
            await app.inject({
              method: 'PUT',
              url: `/cp/accounts/${accountKey}/account-settings`,
              payload: {
                branding: { logo: true, menuColor: true, fontColor: true, welcomeMessage: true },
                organizationStructure: { employers: true, locations: true },
                companyCalendar: { allowed: true },
              },
            })
          ).statusCode,
        ).toBe(200);
      }

      expect(
        (
          await app.inject({
            method: 'PUT',
            url: `/cp/accounts/${enabledKey}/modules`,
            payload: {
              modules: { personal: true, documents: false, benefits: false, payments: false },
            },
          })
        ).statusCode,
      ).toBe(200);

      expect(
        (
          await app.inject({
            method: 'PUT',
            url: `/cp/accounts/${enabledKey}/modules/personal`,
            payload: buildSelectivePersonalPayload({
              allowedFamilies: ['identity', 'contact', 'identifiers'],
            }),
          })
        ).statusCode,
      ).toBe(200);

      expect(
        (
          await app.inject({
            method: 'PUT',
            url: `/cp/accounts/${disabledKey}/modules`,
            payload: {
              modules: { personal: false, documents: false, benefits: false, payments: false },
            },
          })
        ).statusCode,
      ).toBe(200);

      for (const accountKey of [enabledKey, disabledKey]) {
        expect(
          (
            await app.inject({
              method: 'PUT',
              url: `/cp/accounts/${accountKey}/integrations`,
              payload: buildIntegrationsPayload({
                googleAllowed: false,
                microsoftAllowed: false,
              }),
            })
          ).statusCode,
        ).toBe(200);

        expect(
          (
            await app.inject({
              method: 'POST',
              url: `/cp/accounts/${accountKey}/publish`,
              payload: { targetStatus: 'Active' },
            })
          ).statusCode,
        ).toBe(200);
      }

      const enabledTenant = await deps.db
        .selectFrom('tenants')
        .select(['id', 'key'])
        .where('key', '=', enabledKey)
        .executeTakeFirstOrThrow();
      const disabledTenant = await deps.db
        .selectFrom('tenants')
        .select(['id', 'key'])
        .where('key', '=', disabledKey)
        .executeTakeFirstOrThrow();

      const enabledAdmin = await createAdminSession({
        app,
        deps,
        tenantId: enabledTenant.id,
        tenantKey: enabledTenant.key,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });
      const disabledAdmin = await createAdminSession({
        app,
        deps,
        tenantId: disabledTenant.id,
        tenantKey: disabledTenant.key,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const personalRes = await app.inject({
        method: 'GET',
        url: '/settings/modules/personal',
        headers: {
          host: hostForTenant(enabledTenant.key),
          cookie: enabledAdmin.cookie,
        },
      });

      expect(personalRes.statusCode).toBe(200);

      const personal = readJson<PersonalSettingsResponse>(personalRes);
      expect(personal.sectionKey).toBe('personal');
      expect(personal.familyReview.families.map((family) => family.familyKey)).toEqual([
        'identity',
        'contact',
        'identifiers',
      ]);
      expect(personal.familyReview.families[0]).toMatchObject({
        familyKey: 'identity',
        reviewDecision: 'UNREVIEWED',
        canExclude: false,
      });
      expect(personal.familyReview.families[1]).toMatchObject({
        familyKey: 'contact',
        reviewDecision: 'UNREVIEWED',
        canExclude: false,
      });
      expect(personal.familyReview.families[2]).toMatchObject({
        familyKey: 'identifiers',
        reviewDecision: 'UNREVIEWED',
        canExclude: false,
      });
      expect(personal.fieldConfiguration.isLiveInCurrentRepo).toBe(true);
      expect(personal.fieldConfiguration.hiddenVsExcluded.hidden).toContain('Hidden means');
      expect(personal.fieldConfiguration.hiddenVsExcluded.excluded).toContain('Excluded means');
      expect(personal.fieldConfiguration.conflictGuidance.version).toBe(personal.version);
      expect(personal.fieldConfiguration.conflictGuidance.cpRevision).toBe(personal.cpRevision);
      expect(personal.fieldConfiguration.families.map((family) => family.familyKey)).toEqual([
        'identity',
        'contact',
        'identifiers',
      ]);
      expect(personal.fieldConfiguration.families[0]).toMatchObject({
        familyKey: 'identity',
        canExclude: false,
      });
      expect(personal.fieldConfiguration.families[0].fields[0]).toMatchObject({
        fieldKey: 'person.first_name',
        readiness: 'CP_DEFAULT_SELECTED',
        requiredRule: 'LOCKED_REQUIRED',
        canBeExcludedLater: false,
      });
      expect(personal.fieldConfiguration.families[0].fields[1]).toMatchObject({
        fieldKey: 'person.middle_name',
        readiness: 'AVAILABLE_TO_INCLUDE',
        requiredRule: 'TENANT_CHOICE',
        canBeExcludedLater: true,
      });
      expect(personal.fieldConfiguration.families[2].fields[0]).toMatchObject({
        fieldKey: 'person.system_id',
        presentationState: 'READ_ONLY_SYSTEM_MANAGED',
        readiness: 'SYSTEM_MANAGED',
        requiredRule: 'SYSTEM_MANAGED',
        maskingRule: 'LOCKED_SYSTEM_MANAGED',
      });
      expect(personal.sectionBuilder.isLiveInCurrentRepo).toBe(false);

      const disabledPersonalRes = await app.inject({
        method: 'GET',
        url: '/settings/modules/personal',
        headers: {
          host: hostForTenant(disabledTenant.key),
          cookie: disabledAdmin.cookie,
        },
      });

      expect(disabledPersonalRes.statusCode).toBe(404);
    } finally {
      await close();
    }
  });
});
