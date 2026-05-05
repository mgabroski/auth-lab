import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';
import {
  acknowledgeAccess,
  buildCpPersonalCatalogPayload,
  createPublishedSettingsTenant,
  createSettingsAdmin,
  getAccountSettings,
  getPersonalSettings,
  getSettingsBootstrap,
  getSettingsOverview,
  hostForTenant,
  readJson,
  savePersonalFromCurrentDto,
} from '../helpers/settings-fixtures';
import type {
  AccountBrandingCardDto,
  SettingsMutationResultDto,
} from '../../src/modules/settings/settings.types';

describe('settings proof and QA closure', () => {
  it('drives the shipped banner lifecycle, required setup, placeholders, and absent routes end to end', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-proof-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      const tenant = await createPublishedSettingsTenant({ app, deps, accountKey });
      const admin = await createSettingsAdmin({
        app,
        deps,
        tenant,
        email: `settings-proof-admin-${randomUUID().slice(0, 8)}@example.com`,
      });

      const initialBootstrap = await getSettingsBootstrap({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(initialBootstrap.showSetupBanner).toBe(true);
      expect(initialBootstrap.nextAction).toEqual(
        expect.objectContaining({ key: 'access', href: '/admin/settings/access' }),
      );

      const initialOverview = await getSettingsOverview({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(initialOverview.cards.map((card) => card.key)).toEqual([
        'access',
        'account',
        'modules',
        'integrations',
        'communications',
        'workspaceExperience',
      ]);
      expect(initialOverview.cards.some((card) => card.key === 'communications')).toBe(true);
      expect(initialOverview.cards.some((card) => card.title === 'Permissions')).toBe(false);

      const accessMutation = await acknowledgeAccess({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(accessMutation.section).toEqual(
        expect.objectContaining({ key: 'access', status: 'COMPLETE' }),
      );
      expect(accessMutation.aggregate.status).toBe('IN_PROGRESS');

      const afterAccessBootstrap = await getSettingsBootstrap({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(afterAccessBootstrap.showSetupBanner).toBe(true);
      expect(afterAccessBootstrap.nextAction).toEqual(
        expect.objectContaining({ key: 'modules', href: '/admin/settings/modules/personal' }),
      );

      const personalMutation = await savePersonalFromCurrentDto({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(personalMutation.section).toEqual(
        expect.objectContaining({ key: 'personal', status: 'COMPLETE' }),
      );
      expect(personalMutation.aggregate.status).toBe('COMPLETE');

      const completeBootstrap = await getSettingsBootstrap({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(completeBootstrap).toEqual({
        overallStatus: 'COMPLETE',
        showSetupBanner: false,
        nextAction: null,
      });

      const communicationsRes = await app.inject({
        method: 'GET',
        url: '/settings/communications',
        headers: { host: hostForTenant(tenant.tenantKey), cookie: admin.cookie },
      });
      expect(communicationsRes.statusCode).toBe(200);
      expect(
        readJson<{ liveConfigurationAvailable: boolean; mutationEndpointsAvailable: boolean }>(
          communicationsRes,
        ),
      ).toEqual(
        expect.objectContaining({
          liveConfigurationAvailable: false,
          mutationEndpointsAvailable: false,
        }),
      );

      const permissionsRes = await app.inject({
        method: 'GET',
        url: '/settings/permissions',
        headers: { host: hostForTenant(tenant.tenantKey), cookie: admin.cookie },
      });
      expect(permissionsRes.statusCode).toBe(404);
    } finally {
      await close();
    }
  });

  it('keeps Account non-gating and prevents Account saves from fake-completing required setup', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `account-proof-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      const tenant = await createPublishedSettingsTenant({ app, deps, accountKey });
      const admin = await createSettingsAdmin({
        app,
        deps,
        tenant,
        email: `account-proof-admin-${randomUUID().slice(0, 8)}@example.com`,
      });

      const account = await getAccountSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      const branding = account.cards.find(
        (card): card is AccountBrandingCardDto => card.key === 'branding',
      );
      if (!branding) {
        throw new Error('Expected Branding account card in Settings Account fixture.');
      }

      const saveBrandingRes = await app.inject({
        method: 'PUT',
        url: '/settings/account/branding',
        headers: { host: hostForTenant(tenant.tenantKey), cookie: admin.cookie },
        payload: {
          expectedVersion: branding.version,
          expectedCpRevision: branding.cpRevision,
          values: {
            logoUrl: null,
            menuColor: '#0f172a',
            fontColor: '#ffffff',
            welcomeMessage: 'QA proof that Account is non-gating.',
          },
        },
      });
      expect(saveBrandingRes.statusCode).toBe(200);
      const mutation = readJson<SettingsMutationResultDto>(saveBrandingRes);
      expect(mutation.section).toEqual(
        expect.objectContaining({ key: 'account', status: 'IN_PROGRESS' }),
      );
      expect(mutation.aggregate.status).not.toBe('COMPLETE');

      const bootstrap = await getSettingsBootstrap({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(bootstrap.showSetupBanner).toBe(true);
      expect(bootstrap.nextAction?.key).toBe('access');
    } finally {
      await close();
    }
  });

  it('proves CP required review triggers and optional Personal removals through the real cascade path', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `cascade-proof-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      const tenant = await createPublishedSettingsTenant({ app, deps, accountKey });
      const admin = await createSettingsAdmin({
        app,
        deps,
        tenant,
        email: `cascade-proof-admin-${randomUUID().slice(0, 8)}@example.com`,
      });

      await acknowledgeAccess({ app, tenantKey: tenant.tenantKey, cookie: admin.cookie });
      await savePersonalFromCurrentDto({ app, tenantKey: tenant.tenantKey, cookie: admin.cookie });

      const completeBeforeCascade = await getSettingsBootstrap({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(completeBeforeCascade.overallStatus).toBe('COMPLETE');

      const optionalRemovalRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/modules/personal`,
        payload: buildCpPersonalCatalogPayload({ disallowedFieldKeys: ['person.date_of_birth'] }),
      });
      expect(optionalRemovalRes.statusCode).toBe(200);

      const afterOptionalRemoval = await getSettingsBootstrap({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(afterOptionalRemoval.overallStatus).toBe('COMPLETE');
      expect(afterOptionalRemoval.showSetupBanner).toBe(false);

      const personalAfterOptionalRemoval = await getPersonalSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(personalAfterOptionalRemoval.status).toBe('COMPLETE');
      expect(
        personalAfterOptionalRemoval.fieldConfiguration.families
          .flatMap((family) => family.fields)
          .some((field) => field.fieldKey === 'person.date_of_birth'),
      ).toBe(false);

      const requiredAccessChangeRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: {
          loginMethods: { password: true, google: false, microsoft: false },
          mfaPolicy: { adminRequired: true, memberRequired: true },
          signupPolicy: {
            publicSignup: false,
            adminInvitationsAllowed: true,
            allowedDomains: [],
          },
        },
      });
      expect(requiredAccessChangeRes.statusCode).toBe(200);

      const afterRequiredChange = await getSettingsBootstrap({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(afterRequiredChange.overallStatus).toBe('NEEDS_REVIEW');
      expect(afterRequiredChange.showSetupBanner).toBe(true);
      expect(afterRequiredChange.nextAction).toEqual(
        expect.objectContaining({ key: 'access', href: '/admin/settings/access' }),
      );

      const reviewClosure = await acknowledgeAccess({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      expect(reviewClosure.section).toEqual(
        expect.objectContaining({ key: 'access', status: 'COMPLETE' }),
      );
      expect(reviewClosure.aggregate.status).toBe('COMPLETE');
    } finally {
      await close();
    }
  });

  it('preserves tenant isolation when a valid Settings admin cookie is replayed on another tenant host', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      const tenantA = await createPublishedSettingsTenant({
        app,
        deps,
        accountKey: `isolation-a-${randomUUID().slice(0, 8)}`,
      });
      const tenantB = await createPublishedSettingsTenant({
        app,
        deps,
        accountKey: `isolation-b-${randomUUID().slice(0, 8)}`,
      });
      const adminA = await createSettingsAdmin({
        app,
        deps,
        tenant: tenantA,
        email: `isolation-admin-${randomUUID().slice(0, 8)}@example.com`,
      });

      const ownTenantRes = await app.inject({
        method: 'GET',
        url: '/settings/bootstrap',
        headers: { host: hostForTenant(tenantA.tenantKey), cookie: adminA.cookie },
      });
      expect(ownTenantRes.statusCode).toBe(200);

      const crossTenantRes = await app.inject({
        method: 'GET',
        url: '/settings/bootstrap',
        headers: { host: hostForTenant(tenantB.tenantKey), cookie: adminA.cookie },
      });
      expect(crossTenantRes.statusCode).toBe(401);
    } finally {
      await close();
    }
  });
});
