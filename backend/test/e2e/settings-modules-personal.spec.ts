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
import { createAdminSession } from '../helpers/create-admin-session';
import { buildTestApp } from '../helpers/build-test-app';
import type {
  ModulesHubResponse,
  PersonalSettingsResponse,
  SettingsMutationResultDto,
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

async function provisionTenant(
  app: Awaited<ReturnType<typeof buildTestApp>>['app'],
  accountKey: string,
) {
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
            payments: false,
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
        payload: buildIntegrationsPayload({ googleAllowed: false, microsoftAllowed: false }),
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

function buildSavePayload(personal: PersonalSettingsResponse) {
  return {
    expectedVersion: personal.version,
    expectedCpRevision: personal.cpRevision,
    families: personal.familyReview.families.map((family) => ({
      familyKey: family.familyKey,
      reviewDecision: family.reviewDecision,
    })),
    fields: personal.fieldConfiguration.families.flatMap((family) =>
      family.fields.map((field) => ({
        fieldKey: field.fieldKey,
        included: field.included,
        required: field.required,
        masked: field.masked,
      })),
    ),
    sections: personal.sectionBuilder.sections.map((section) => ({
      sectionId: section.sectionId,
      name: section.name,
      order: section.order,
      fields: section.fields.map((field) => ({
        fieldKey: field.fieldKey,
        order: field.order,
      })),
    })),
  };
}

describe('settings Personal builder and save', () => {
  it('returns a truthful modules hub with one live Personal card and placeholder-only future modules', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await provisionTenant(app, accountKey);

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
      expect(modules.visibleModuleKeys).toEqual(['personal', 'documents']);
      expect(modules.cards[0]).toEqual(
        expect.objectContaining({
          key: 'personal',
          classification: 'LIVE',
          href: '/admin/settings/modules/personal',
          status: 'NOT_STARTED',
        }),
      );
    } finally {
      await close();
    }
  });

  it('returns the final Personal DTO with backend-generated default sections', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `personal-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await provisionTenant(app, accountKey);

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

      const personalRes = await app.inject({
        method: 'GET',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });

      expect(personalRes.statusCode).toBe(200);
      const personal = readJson<PersonalSettingsResponse>(personalRes);
      expect(personal.familyReview.key).toBe('familyReview');
      expect(personal.fieldConfiguration.key).toBe('fieldConfiguration');
      expect(personal.sectionBuilder.key).toBe('sectionBuilder');
      expect(personal.saveActionLabel).toBe('Save Personal Configuration');
      expect(personal.sectionBuilder.sections.length).toBeGreaterThan(0);
      expect(personal.progress.reviewedFamiliesCount).toBe(0);
      expect(personal.progress.requiredFieldsReady).toBe(false);
      expect(personal.progress.sectionAssignmentsReady).toBe(false);
      expect(personal.progress.blockers).toContain('No family reviewed yet.');
      expect(personal.progress.blockers).toContain(
        'Required-floor fields still need configuration.',
      );
      expect(personal.progress.blockers).toContain('Section assignments still need save.');
    } finally {
      await close();
    }
  });

  it('saves Personal with the canonical full-replacement contract and completes the Personal boundary', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `save-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await provisionTenant(app, accountKey);

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

      const readRes = await app.inject({
        method: 'GET',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      const personal = readJson<PersonalSettingsResponse>(readRes);

      const payload = buildSavePayload(personal);

      const saveRes = await app.inject({
        method: 'PUT',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload,
      });

      expect(saveRes.statusCode).toBe(200);
      const mutation = readJson<SettingsMutationResultDto>(saveRes);
      expect(mutation.section.key).toBe('personal');
      expect(mutation.section.status).toBe('COMPLETE');
      expect(mutation.aggregate.status).toBe('IN_PROGRESS');

      const savedFamilies = await deps.db
        .selectFrom('tenant_personal_family_state')
        .selectAll()
        .where('tenant_id', '=', tenant.id)
        .execute();
      const savedSections = await deps.db
        .selectFrom('tenant_sections')
        .selectAll()
        .where('tenant_id', '=', tenant.id)
        .execute();
      expect(savedFamilies.length).toBe(payload.families.length);
      expect(savedSections.length).toBe(payload.sections.length);
    } finally {
      await close();
    }
  });

  it('returns a CP revision conflict when the submitted full replacement no longer matches current CP truth', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `cp-conflict-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await provisionTenant(app, accountKey);

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

      const readRes = await app.inject({
        method: 'GET',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      const personal = readJson<PersonalSettingsResponse>(readRes);

      const stalePayload = buildSavePayload(personal);

      const updatedPersonalPayload = buildValidPersonalPayload();
      updatedPersonalPayload.fields = updatedPersonalPayload.fields.map((field) =>
        field.fieldKey === 'person.middle_name'
          ? { ...field, isAllowed: false, defaultSelected: false }
          : field,
      );

      const cpMutationRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/modules/personal`,
        payload: updatedPersonalPayload,
      });
      expect(cpMutationRes.statusCode).toBe(200);

      const staleSaveRes = await app.inject({
        method: 'PUT',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: stalePayload,
      });

      expect(staleSaveRes.statusCode).toBe(409);
      const body = readJson<{ error: { code: string; message: string } }>(staleSaveRes);
      expect(body).toEqual({
        error: {
          code: 'CONFLICT',
          message:
            'Personal settings changed while you were editing them. Refresh the page and review the latest Personal configuration before saving again.',
        },
      });
    } finally {
      await close();
    }
  });

  it('rejects version conflicts and empty sections honestly', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `conflict-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await provisionTenant(app, accountKey);

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

      const initialReadRes = await app.inject({
        method: 'GET',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      const initialPersonal = readJson<PersonalSettingsResponse>(initialReadRes);

      const firstPayload = buildSavePayload(initialPersonal);
      const renamedPayload = {
        ...firstPayload,
        sections: firstPayload.sections.map((section, index) =>
          index === 0 ? { ...section, name: `${section.name} Updated` } : section,
        ),
      };

      const successfulSaveRes = await app.inject({
        method: 'PUT',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: renamedPayload,
      });

      expect(successfulSaveRes.statusCode).toBe(200);
      const successfulMutation = readJson<SettingsMutationResultDto>(successfulSaveRes);

      const staleVersionPayload = {
        ...renamedPayload,
        expectedVersion: initialPersonal.version,
      };

      const staleVersionRes = await app.inject({
        method: 'PUT',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: staleVersionPayload,
      });

      expect(staleVersionRes.statusCode).toBe(409);

      const invalidPayload = {
        ...renamedPayload,
        expectedVersion: successfulMutation.section.version,
        expectedCpRevision: successfulMutation.section.cpRevision,
        sections: [
          {
            sectionId: 'empty',
            name: 'Empty',
            order: 0,
            fields: [],
          },
        ],
      };

      const invalidRes = await app.inject({
        method: 'PUT',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: invalidPayload,
      });

      expect(invalidRes.statusCode).toBe(400);
    } finally {
      await close();
    }
  });
});
