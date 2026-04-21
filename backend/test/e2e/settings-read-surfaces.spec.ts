import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';
import { up as upSettingsFoundationMigration } from '../../src/shared/db/migrations/0017_settings_foundation';
import { createAdminSession } from '../helpers/create-admin-session';
import type {
  SettingsBootstrapResponse,
  SettingsOverviewCardDto,
  SettingsOverviewCardKey,
  SettingsOverviewResponse,
} from '../../src/modules/settings/settings.types';

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

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

describe('settings phase 2 read surfaces', () => {
  it('returns bootstrap-safe native setup truth after the legacy auth bridge runs', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);

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

      const ackRes = await app.inject({
        method: 'POST',
        url: '/auth/workspace-setup-ack',
        headers: {
          host: hostForTenant(tenant.key),
          cookie: admin.cookie,
        },
      });
      expect(ackRes.statusCode).toBe(200);

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
      const communicationsCard = requireCard(overview, 'communications');
      const workspaceExperienceCard = requireCard(overview, 'workspaceExperience');

      expect(overview.overallStatus).toBe('NOT_STARTED');
      expect(overview.cards.map((card) => card.key)).toEqual([
        'access',
        'account',
        'modules',
        'integrations',
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
});
