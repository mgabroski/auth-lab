import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';
import { up as upSettingsFoundationMigration } from '../../src/shared/db/migrations/0017_settings_foundation';
import { createAdminSession } from '../helpers/create-admin-session';

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

async function recomputeCompletedAggregate(params: {
  deps: Awaited<ReturnType<typeof buildTestApp>>['deps'];
  tenantId: string;
  actorUserId: string;
  personalRequired: boolean;
}): Promise<void> {
  const appliedCpRevision =
    await params.deps.settings.foundationRepo.findCurrentCpRevisionForTenant(params.tenantId);

  await params.deps.settings.stateService.recomputeAggregate({
    tenantId: params.tenantId,
    appliedCpRevision,
    transitionAt: new Date(),
    personalRequired: params.personalRequired,
    actorUserId: params.actorUserId,
  });
}

describe('settings phase 2 CP cascade', () => {
  it('marks Access as NEEDS_REVIEW when a published tenant changes required access allowance truth', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `cascade-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'Cascade Tenant',
          accountKey,
        },
      });
      expect(createRes.statusCode).toBe(201);

      const accessRes = await app.inject({
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
          modules: { personal: false, documents: false, benefits: false, payments: false },
        },
      });
      expect(modulesRes.statusCode).toBe(200);

      const publishRes = await app.inject({
        method: 'POST',
        url: `/cp/accounts/${accountKey}/publish`,
        payload: { targetStatus: 'Active' },
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

      const ackRes = await app.inject({
        method: 'POST',
        url: '/auth/workspace-setup-ack',
        headers: {
          host: hostForTenant(tenant.key),
          cookie: admin.cookie,
        },
      });
      expect(ackRes.statusCode).toBe(200);

      await recomputeCompletedAggregate({
        deps,
        tenantId: tenant.id,
        actorUserId: admin.userId,
        personalRequired: false,
      });

      const before = await deps.settings.foundationRepo.getStateBundle(tenant.id);
      expect(before).toBeDefined();
      expect(before?.aggregate.overallStatus).toBe('COMPLETE');
      expect(before?.sections.access.status).toBe('COMPLETE');

      const previousRevision = before!.sections.access.appliedCpRevision;

      const changedAccessRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: {
          loginMethods: { password: true, google: false, microsoft: false },
          mfaPolicy: { adminRequired: true, memberRequired: true },
          signupPolicy: {
            publicSignup: false,
            adminInvitationsAllowed: true,
            allowedDomains: ['example.com'],
          },
        },
      });
      expect(changedAccessRes.statusCode).toBe(200);

      const after = await deps.settings.foundationRepo.getStateBundle(tenant.id);
      expect(after).toBeDefined();
      expect(after?.aggregate.overallStatus).toBe('NEEDS_REVIEW');
      expect(after?.sections.access.status).toBe('NEEDS_REVIEW');
      expect(after?.sections.access.appliedCpRevision).toBe(previousRevision + 1);
    } finally {
      await close();
    }
  });

  it('keeps aggregate COMPLETE when only non-gating account allowance truth changes after completion', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `cascade-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'Cascade Non Gating Tenant',
          accountKey,
        },
      });
      expect(createRes.statusCode).toBe(201);

      const accessRes = await app.inject({
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
          modules: { personal: false, documents: false, benefits: false, payments: false },
        },
      });
      expect(modulesRes.statusCode).toBe(200);

      const publishRes = await app.inject({
        method: 'POST',
        url: `/cp/accounts/${accountKey}/publish`,
        payload: { targetStatus: 'Active' },
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

      const ackRes = await app.inject({
        method: 'POST',
        url: '/auth/workspace-setup-ack',
        headers: {
          host: hostForTenant(tenant.key),
          cookie: admin.cookie,
        },
      });
      expect(ackRes.statusCode).toBe(200);

      await recomputeCompletedAggregate({
        deps,
        tenantId: tenant.id,
        actorUserId: admin.userId,
        personalRequired: false,
      });

      const before = await deps.settings.foundationRepo.getStateBundle(tenant.id);
      expect(before).toBeDefined();
      expect(before?.aggregate.overallStatus).toBe('COMPLETE');

      const previousRevision = before!.sections.account.appliedCpRevision;

      const changedAccountSettingsRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/account-settings`,
        payload: {
          branding: { logo: false, menuColor: false, fontColor: true, welcomeMessage: true },
          organizationStructure: { employers: true, locations: true },
          companyCalendar: { allowed: true },
        },
      });
      expect(changedAccountSettingsRes.statusCode).toBe(200);

      const after = await deps.settings.foundationRepo.getStateBundle(tenant.id);
      expect(after).toBeDefined();
      expect(after?.aggregate.overallStatus).toBe('COMPLETE');
      expect(after?.sections.account.appliedCpRevision).toBe(previousRevision + 1);
      expect(after?.sections.account.status).toBe('NOT_STARTED');
    } finally {
      await close();
    }
  });
});
