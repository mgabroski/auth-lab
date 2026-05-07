/**
 * backend/test/helpers/settings-fixtures.ts
 *
 * WHY:
 * - Settings proof tests need deterministic tenant states that reviewers can
 *   reason about without hand-written SQL or hidden DB mutation shortcuts.
 * - This helper builds those states through the shipped Control Plane and
 *   Settings HTTP contracts wherever possible, then returns tenant/admin handles
 *   for focused assertions.
 *
 * RULES:
 * - Test-only helper. Never import from production code.
 * - CP allowance truth is produced through /cp/accounts routes.
 * - Tenant Settings truth is changed through /settings routes.
 * - Direct DB reads are limited to resolving IDs for assertions and admin setup.
 */

import { expect } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type { AppDeps } from '../../src/app/di';
import {
  EDITABLE_PERSONAL_FIELD_CATALOG,
  INTEGRATION_CATALOG,
  PERSONAL_FAMILY_DEFAULTS,
  REQUIRED_BASELINE_PERSONAL_FIELD_KEYS,
} from '../../src/modules/control-plane/accounts/cp-accounts.catalog';
import type {
  SaveCpIntegrationsInput,
  SaveCpPersonalInput,
} from '../../src/modules/control-plane/accounts/cp-accounts.schemas';
import type {
  AccessSettingsDto,
  AccountSettingsDto,
  PersonalSettingsDto,
  SettingsBootstrapDto,
  SettingsMutationResultDto,
  SettingsOverviewDto,
} from '../../src/modules/settings/settings.types';
import type { AdminSessionResult } from './create-admin-session';
import { createAdminSession } from './create-admin-session';
import { hostForTenant } from './tenant-host';

export { hostForTenant } from './tenant-host';

export type SettingsTenantFixture = {
  tenantId: string;
  tenantKey: string;
  accountKey: string;
};

type InjectResponse = {
  statusCode: number;
  json: () => unknown;
};

export function readJson<T>(res: InjectResponse): T {
  return res.json() as T;
}

function expectStatus(res: InjectResponse, expectedStatus: number, context: string): void {
  expect(res.statusCode, context).toBe(expectedStatus);
}

export function buildCpPersonalCatalogPayload(params?: {
  disallowedFamilyKeys?: string[];
  disallowedFieldKeys?: string[];
}): SaveCpPersonalInput {
  const disallowedFamilies = new Set(params?.disallowedFamilyKeys ?? []);
  const disallowedFields = new Set(params?.disallowedFieldKeys ?? []);
  const requiredBaselineFields = new Set(REQUIRED_BASELINE_PERSONAL_FIELD_KEYS);

  return {
    families: PERSONAL_FAMILY_DEFAULTS.map((family) => ({
      familyKey: family.familyKey,
      isAllowed: family.defaultAllowed && !disallowedFamilies.has(family.familyKey),
    })),
    fields: EDITABLE_PERSONAL_FIELD_CATALOG.map((field) => {
      const fieldIsRequiredBaseline = requiredBaselineFields.has(field.fieldKey);
      const familyIsAllowed = !disallowedFamilies.has(field.familyKey);
      const fieldIsAllowed = fieldIsRequiredBaseline
        ? true
        : familyIsAllowed && field.defaultAllowed && !disallowedFields.has(field.fieldKey);

      return {
        fieldKey: field.fieldKey,
        isAllowed: fieldIsAllowed,
        defaultSelected:
          fieldIsAllowed && field.defaultSelected && !disallowedFields.has(field.fieldKey),
      };
    }),
  };
}

export function buildCpIntegrationsPayload(params?: {
  googleAllowed?: boolean;
  microsoftAllowed?: boolean;
}): SaveCpIntegrationsInput {
  return {
    integrations: INTEGRATION_CATALOG.map((integration) => ({
      integrationKey: integration.integrationKey,
      isAllowed:
        integration.integrationKey === 'integration.sso.google'
          ? (params?.googleAllowed ?? false)
          : integration.integrationKey === 'integration.sso.microsoft'
            ? (params?.microsoftAllowed ?? false)
            : integration.defaultAllowed,
      capabilities: integration.capabilities.map((capability) => ({
        capabilityKey: capability.capabilityKey,
        isAllowed: capability.defaultAllowed,
      })),
    })),
  };
}

export function buildPersonalSavePayload(personal: PersonalSettingsDto) {
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

export async function createPublishedSettingsTenant(opts: {
  app: FastifyInstance;
  deps: AppDeps;
  accountKey: string;
  accountName?: string;
  personalEnabled?: boolean;
  documentsEnabled?: boolean;
  publicSignup?: boolean;
  googleLoginEnabled?: boolean;
  microsoftLoginEnabled?: boolean;
  googleIntegrationAllowed?: boolean;
  microsoftIntegrationAllowed?: boolean;
}): Promise<SettingsTenantFixture> {
  const personalEnabled = opts.personalEnabled ?? true;
  const googleLoginEnabled = opts.googleLoginEnabled ?? false;
  const microsoftLoginEnabled = opts.microsoftLoginEnabled ?? false;
  const googleIntegrationAllowed = opts.googleIntegrationAllowed ?? googleLoginEnabled;
  const microsoftIntegrationAllowed = opts.microsoftIntegrationAllowed ?? microsoftLoginEnabled;

  const createRes = await opts.app.inject({
    method: 'POST',
    url: '/cp/accounts',
    payload: {
      accountName: opts.accountName ?? `QA Settings ${opts.accountKey}`,
      accountKey: opts.accountKey,
    },
  });
  expectStatus(createRes, 201, 'create CP account fixture');

  const integrationsRes = await opts.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${opts.accountKey}/integrations`,
    payload: buildCpIntegrationsPayload({
      googleAllowed: googleIntegrationAllowed,
      microsoftAllowed: microsoftIntegrationAllowed,
    }),
  });
  expectStatus(integrationsRes, 200, 'save CP integrations fixture');

  const accessRes = await opts.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${opts.accountKey}/access`,
    payload: {
      loginMethods: {
        password: true,
        google: googleLoginEnabled,
        microsoft: microsoftLoginEnabled,
      },
      mfaPolicy: {
        adminRequired: true,
        memberRequired: false,
      },
      signupPolicy: {
        publicSignup: opts.publicSignup ?? false,
        adminInvitationsAllowed: true,
        allowedDomains: [],
      },
    },
  });
  expectStatus(accessRes, 200, 'save CP access fixture');

  const accountSettingsRes = await opts.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${opts.accountKey}/account-settings`,
    payload: {
      branding: { logo: true, menuColor: true, fontColor: true, welcomeMessage: true },
      organizationStructure: { employers: true, locations: true },
      companyCalendar: { allowed: true },
    },
  });
  expectStatus(accountSettingsRes, 200, 'save CP account settings fixture');

  const modulesRes = await opts.app.inject({
    method: 'PUT',
    url: `/cp/accounts/${opts.accountKey}/modules`,
    payload: {
      modules: {
        personal: personalEnabled,
        documents: opts.documentsEnabled ?? true,
        benefits: false,
        payments: false,
      },
    },
  });
  expectStatus(modulesRes, 200, 'save CP modules fixture');

  if (personalEnabled) {
    const personalRes = await opts.app.inject({
      method: 'PUT',
      url: `/cp/accounts/${opts.accountKey}/modules/personal`,
      payload: buildCpPersonalCatalogPayload(),
    });
    expectStatus(personalRes, 200, 'save CP Personal catalog fixture');
  }

  const publishRes = await opts.app.inject({
    method: 'POST',
    url: `/cp/accounts/${opts.accountKey}/publish`,
    payload: { targetStatus: 'Active' },
  });
  expectStatus(publishRes, 200, 'publish CP account fixture');

  const tenant = await opts.deps.db
    .selectFrom('tenants')
    .select(['id', 'key'])
    .where('key', '=', opts.accountKey)
    .executeTakeFirstOrThrow();

  return {
    tenantId: tenant.id,
    tenantKey: tenant.key,
    accountKey: opts.accountKey,
  };
}

export async function createSettingsAdmin(opts: {
  app: FastifyInstance;
  deps: AppDeps;
  tenant: SettingsTenantFixture;
  email: string;
  password?: string;
}): Promise<AdminSessionResult> {
  return createAdminSession({
    app: opts.app,
    deps: opts.deps,
    tenantId: opts.tenant.tenantId,
    tenantKey: opts.tenant.tenantKey,
    email: opts.email,
    password: opts.password ?? 'Password123!',
  });
}

export async function getSettingsBootstrap(opts: {
  app: FastifyInstance;
  tenantKey: string;
  cookie: string;
}): Promise<SettingsBootstrapDto> {
  const res = await opts.app.inject({
    method: 'GET',
    url: '/settings/bootstrap',
    headers: { host: hostForTenant(opts.tenantKey), cookie: opts.cookie },
  });
  expectStatus(res, 200, 'read Settings bootstrap fixture');
  return readJson<SettingsBootstrapDto>(res);
}

export async function getSettingsOverview(opts: {
  app: FastifyInstance;
  tenantKey: string;
  cookie: string;
}): Promise<SettingsOverviewDto> {
  const res = await opts.app.inject({
    method: 'GET',
    url: '/settings/overview',
    headers: { host: hostForTenant(opts.tenantKey), cookie: opts.cookie },
  });
  expectStatus(res, 200, 'read Settings overview fixture');
  return readJson<SettingsOverviewDto>(res);
}

export async function getAccessSettings(opts: {
  app: FastifyInstance;
  tenantKey: string;
  cookie: string;
}): Promise<AccessSettingsDto> {
  const res = await opts.app.inject({
    method: 'GET',
    url: '/settings/access',
    headers: { host: hostForTenant(opts.tenantKey), cookie: opts.cookie },
  });
  expectStatus(res, 200, 'read Access settings fixture');
  return readJson<AccessSettingsDto>(res);
}

export async function acknowledgeAccess(opts: {
  app: FastifyInstance;
  tenantKey: string;
  cookie: string;
}): Promise<SettingsMutationResultDto> {
  const access = await getAccessSettings(opts);
  const res = await opts.app.inject({
    method: 'POST',
    url: '/settings/access/acknowledge',
    headers: { host: hostForTenant(opts.tenantKey), cookie: opts.cookie },
    payload: {
      expectedVersion: access.version,
      expectedCpRevision: access.cpRevision,
    },
  });
  expectStatus(res, 200, 'acknowledge Access fixture');
  return readJson<SettingsMutationResultDto>(res);
}

export async function getAccountSettings(opts: {
  app: FastifyInstance;
  tenantKey: string;
  cookie: string;
}): Promise<AccountSettingsDto> {
  const res = await opts.app.inject({
    method: 'GET',
    url: '/settings/account',
    headers: { host: hostForTenant(opts.tenantKey), cookie: opts.cookie },
  });
  expectStatus(res, 200, 'read Account settings fixture');
  return readJson<AccountSettingsDto>(res);
}

export async function getPersonalSettings(opts: {
  app: FastifyInstance;
  tenantKey: string;
  cookie: string;
}): Promise<PersonalSettingsDto> {
  const res = await opts.app.inject({
    method: 'GET',
    url: '/settings/modules/personal',
    headers: { host: hostForTenant(opts.tenantKey), cookie: opts.cookie },
  });
  expectStatus(res, 200, 'read Personal settings fixture');
  return readJson<PersonalSettingsDto>(res);
}

export async function savePersonalFromCurrentDto(opts: {
  app: FastifyInstance;
  tenantKey: string;
  cookie: string;
}): Promise<SettingsMutationResultDto> {
  const personal = await getPersonalSettings(opts);
  const payload = buildPersonalSavePayload(personal);
  const res = await opts.app.inject({
    method: 'PUT',
    url: '/settings/modules/personal',
    headers: { host: hostForTenant(opts.tenantKey), cookie: opts.cookie },
    payload,
  });
  expectStatus(res, 200, 'save Personal fixture');
  return readJson<SettingsMutationResultDto>(res);
}
