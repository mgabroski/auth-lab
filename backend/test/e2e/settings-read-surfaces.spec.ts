import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';
import { up as upSettingsFoundationMigration } from '../../src/shared/db/migrations/0017_settings_foundation';
import { up as upSettingsAccountMigration } from '../../src/shared/db/migrations/0018_settings_account';
import { createAdminSession } from '../helpers/create-admin-session';
import { acknowledgeAccess } from '../helpers/settings-fixtures';
import type {
  SettingsBootstrapResponse,
  SettingsOverviewCardDto,
  SettingsOverviewCardKey,
  SettingsOverviewResponse,
  PlaceholderPageResponse,
} from '../../src/modules/settings/settings.types';
import { hostForTenant } from '../helpers/tenant-host';

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function requireCard(
  overview: SettingsOverviewResponse,
  key: SettingsOverviewCardKey,
): SettingsOverviewCardDto {
  const card = overview.cards.find((candidate) => candidate.key === key);
  expect(card).toBeDefined();

  return card as SettingsOverviewCardDto;
}

describe('settings read surfaces', () => {
  it('returns bootstrap-safe native setup truth after Access is acknowledged through Settings', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await deps.db
        .insertInto('tenants')
        .values({
          key: `settings-${randomUUID().slice(0, 8)}`,
          name: 'Settings Native Tenant',
          is_active: true,
          public_signup_enabled: false,
          admin_invite_required: false,
          member_mfa_required: false,
          allowed_email_domains: [],
          allowed_sso: [],
          setup_completed_at: null,
        })
        .returning(['id', 'key'])
        .executeTakeFirstOrThrow();

      await deps.settings.foundationRepo.ensureFoundationRows({
        tenantId: tenant.id,
        appliedCpRevision: 0,
        creationReasonCode: 'FOUNDATION_INITIALIZED',
        transitionAt: new Date('2026-04-21T10:00:00.000Z'),
      });

      const admin = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      await acknowledgeAccess({
        app,
        tenantKey: tenant.key,
        cookie: admin.cookie,
      });

      const bootstrapRes = await app.inject({
        method: 'GET',
        url: '/settings/bootstrap',
        headers: {
          host: hostForTenant(tenant.key),
          cookie: admin.cookie,
        },
      });

      expect(bootstrapRes.statusCode).toBe(200);

      const bootstrap = readJson<SettingsBootstrapResponse>(bootstrapRes);

      expect(bootstrap).toEqual({
        overallStatus: 'IN_PROGRESS',
        showSetupBanner: true,
        nextAction: {
          key: 'modules',
          label: 'Continue Personal setup',
          href: '/admin/settings/modules/personal',
        },
      });
    } finally {
      await close();
    }
  });

  it('returns overview cards with live, navigation-only, placeholder, and absent treatment rules', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'Settings Overview Tenant',
          accountKey,
        },
      });
      expect(createRes.statusCode).toBe(201);

      const integrationsRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/integrations`,
        payload: {
          integrations: [
            {
              integrationKey: 'integration.adp',
              isAllowed: false,
              capabilities: [
                { capabilityKey: 'integration.adp.data_sync', isAllowed: false },
                { capabilityKey: 'integration.adp.import_enabled', isAllowed: false },
                { capabilityKey: 'integration.adp.import_rules', isAllowed: false },
                { capabilityKey: 'integration.adp.field_mapping', isAllowed: false },
              ],
            },
            {
              integrationKey: 'integration.hint',
              isAllowed: false,
              capabilities: [
                { capabilityKey: 'integration.hint.data_sync', isAllowed: false },
                { capabilityKey: 'integration.hint.import_enabled', isAllowed: false },
                { capabilityKey: 'integration.hint.import_rules', isAllowed: false },
                { capabilityKey: 'integration.hint.field_mapping', isAllowed: false },
              ],
            },
            {
              integrationKey: 'integration.istream',
              isAllowed: false,
              capabilities: [
                { capabilityKey: 'integration.istream.data_sync', isAllowed: false },
                { capabilityKey: 'integration.istream.import_enabled', isAllowed: false },
                { capabilityKey: 'integration.istream.import_rules', isAllowed: false },
                { capabilityKey: 'integration.istream.field_mapping', isAllowed: false },
              ],
            },
            {
              integrationKey: 'integration.stripe',
              isAllowed: false,
              capabilities: [
                { capabilityKey: 'integration.stripe.payments_surface', isAllowed: false },
              ],
            },
            {
              integrationKey: 'integration.sso.google',
              isAllowed: true,
              capabilities: [],
            },
            {
              integrationKey: 'integration.sso.microsoft',
              isAllowed: false,
              capabilities: [],
            },
          ],
        },
      });
      expect(integrationsRes.statusCode).toBe(200);

      const accessRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: {
          loginMethods: {
            password: true,
            google: true,
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

      const accountSettingsRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/account-settings`,
        payload: {
          branding: { logo: true, menuColor: true, fontColor: true, welcomeMessage: true },
          organizationStructure: { employers: true, locations: true },
          companyCalendar: { allowed: true },
        },
      });
      expect(accountSettingsRes.statusCode).toBe(200);

      const modulesRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/modules`,
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

      const publishRes = await app.inject({
        method: 'POST',
        url: `/cp/accounts/${accountKey}/publish`,
        payload: {
          targetStatus: 'Active',
        },
      });
      expect(publishRes.statusCode).toBe(200);

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

      const overviewRes = await app.inject({
        method: 'GET',
        url: '/settings/overview',
        headers: {
          host: hostForTenant(tenant.key),
          cookie: admin.cookie,
        },
      });

      expect(overviewRes.statusCode).toBe(200);

      const overview = readJson<SettingsOverviewResponse>(overviewRes);
      const accessCard = requireCard(overview, 'access');
      const modulesCard = requireCard(overview, 'modules');
      const integrationsCard = requireCard(overview, 'integrations');
      const peopleTeamsCard = requireCard(overview, 'peopleTeams');
      const communicationsCard = requireCard(overview, 'communications');
      const workspaceExperienceCard = requireCard(overview, 'workspaceExperience');

      expect(overview.overallStatus).toBe('NOT_STARTED');
      expect(overview.cards.map((card) => card.key)).toEqual([
        'access',
        'account',
        'modules',
        'integrations',
        'peopleTeams',
        'communications',
        'workspaceExperience',
      ]);

      expect(accessCard).toMatchObject({
        classification: 'REQUIRED_GATING',
        status: 'NOT_STARTED',
        isRequired: true,
      });

      expect(modulesCard).toMatchObject({
        classification: 'NAVIGATION_ONLY',
        status: 'NOT_STARTED',
      });

      expect(integrationsCard).toMatchObject({
        classification: 'LIVE_NON_GATING',
        status: 'NOT_STARTED',
      });
      expect(integrationsCard.warnings.join(' ')).toContain('runtime readiness is unavailable');

      expect(peopleTeamsCard).toMatchObject({
        classification: 'LIVE_NON_GATING',
        status: 'MANAGEMENT',
        isRequired: false,
        href: '/admin/settings/people-teams',
      });

      expect(communicationsCard).toMatchObject({
        classification: 'PLACEHOLDER_ONLY',
        status: 'PLACEHOLDER',
      });

      expect(workspaceExperienceCard).toMatchObject({
        classification: 'PLACEHOLDER_ONLY',
        status: 'PLACEHOLDER',
        href: null,
      });
    } finally {
      await close();
    }
  });

  it('shows the safe Operational Access shell card only when the tenant capability is enabled', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const disabledTenant = await deps.db
        .insertInto('tenants')
        .values({
          key: `settings-disabled-${randomUUID().slice(0, 8)}`,
          name: 'Operational Access Disabled Tenant',
          is_active: true,
          public_signup_enabled: false,
          admin_invite_required: false,
          member_mfa_required: false,
          allowed_email_domains: [],
          allowed_sso: [],
          setup_completed_at: null,
        })
        .returning(['id', 'key'])
        .executeTakeFirstOrThrow();

      const enabledTenant = await deps.db
        .insertInto('tenants')
        .values({
          key: `settings-enabled-${randomUUID().slice(0, 8)}`,
          name: 'Operational Access Enabled Tenant',
          is_active: true,
          public_signup_enabled: false,
          admin_invite_required: false,
          member_mfa_required: false,
          operational_access_enabled: true,
          allowed_email_domains: [],
          allowed_sso: [],
          setup_completed_at: null,
        })
        .returning(['id', 'key'])
        .executeTakeFirstOrThrow();

      for (const tenant of [disabledTenant, enabledTenant]) {
        await deps.settings.foundationRepo.ensureFoundationRows({
          tenantId: tenant.id,
          appliedCpRevision: 0,
          creationReasonCode: 'FOUNDATION_INITIALIZED',
          transitionAt: new Date('2026-05-19T10:00:00.000Z'),
        });
      }

      const disabledAdmin = await createAdminSession({
        app,
        deps,
        tenantId: disabledTenant.id,
        tenantKey: disabledTenant.key,
        email: `admin-disabled-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });
      const enabledAdmin = await createAdminSession({
        app,
        deps,
        tenantId: enabledTenant.id,
        tenantKey: enabledTenant.key,
        email: `admin-enabled-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const disabledOverviewRes = await app.inject({
        method: 'GET',
        url: '/settings/overview',
        headers: {
          host: hostForTenant(disabledTenant.key),
          cookie: disabledAdmin.cookie,
        },
      });
      const enabledOverviewRes = await app.inject({
        method: 'GET',
        url: '/settings/overview',
        headers: {
          host: hostForTenant(enabledTenant.key),
          cookie: enabledAdmin.cookie,
        },
      });

      expect(disabledOverviewRes.statusCode).toBe(200);
      expect(enabledOverviewRes.statusCode).toBe(200);

      const disabledOverview = readJson<SettingsOverviewResponse>(disabledOverviewRes);
      const enabledOverview = readJson<SettingsOverviewResponse>(enabledOverviewRes);

      expect(disabledOverview.cards.map((card) => card.key)).not.toContain('operationalAccess');

      const operationalAccessCard = requireCard(enabledOverview, 'operationalAccess');
      expect(operationalAccessCard).toMatchObject({
        title: 'Operational Access',
        href: '/admin/settings/operational-access',
        classification: 'LIVE_NON_GATING',
        status: 'MANAGEMENT',
        isRequired: false,
      });
      expect(operationalAccessCard.warnings.join(' ')).toContain(
        'Group grant and Responsible For configuration foundations are available, but resolver behavior and runtime Agent visibility are not shipped yet',
      );
    } finally {
      await close();
    }
  });

  it('serves only the Communications placeholder read route and keeps Workspace Experience plus Permissions route-absent', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();

      const tenant = await deps.db
        .insertInto('tenants')
        .values({
          key: `settings-${randomUUID().slice(0, 8)}`,
          name: 'Settings Placeholder Tenant',
          is_active: true,
          public_signup_enabled: false,
          admin_invite_required: false,
          member_mfa_required: false,
          allowed_email_domains: [],
          allowed_sso: [],
          setup_completed_at: null,
        })
        .returning(['id', 'key'])
        .executeTakeFirstOrThrow();

      const admin = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const authHeaders = {
        host: hostForTenant(tenant.key),
        cookie: admin.cookie,
      };

      const communicationsRes = await app.inject({
        method: 'GET',
        url: '/settings/communications',
        headers: authHeaders,
      });

      expect(communicationsRes.statusCode).toBe(200);
      const placeholder = readJson<PlaceholderPageResponse>(communicationsRes);
      expect(placeholder).toMatchObject({
        key: 'communications',
        status: 'PLACEHOLDER',
        treatment: 'PLACEHOLDER_ROUTE_ONLY',
        liveConfigurationAvailable: false,
        mutationEndpointsAvailable: false,
        backHref: '/admin/settings',
      });
      expect(placeholder.notes.join(' ')).toContain('Email templates are not configurable in v1.');
      expect(placeholder.notes.join(' ')).toContain(
        'Notification rules are not configurable in v1.',
      );

      for (const candidate of [
        { method: 'POST', url: '/settings/communications' },
        { method: 'PUT', url: '/settings/communications' },
        { method: 'GET', url: '/settings/workspace-experience' },
        { method: 'POST', url: '/settings/workspace-experience' },
        { method: 'GET', url: '/settings/permissions' },
        { method: 'POST', url: '/settings/permissions' },
      ] as const) {
        const res = await app.inject({
          method: candidate.method,
          url: candidate.url,
          headers: authHeaders,
        });
        expect(res.statusCode).toBe(404);
      }
    } finally {
      await close();
    }
  });
});
