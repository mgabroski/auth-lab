import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import type {
  CpAccountDetail,
  CpAccountReview,
} from '../../src/modules/control-plane/accounts/cp-accounts.types';
import { buildTestApp } from '../helpers/build-test-app';

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

describe('cp accounts settings handoff integration boundary', () => {
  it('stays producer-only while exposing a canonical Settings handoff snapshot', async () => {
    const { app, close, deps, reset } = await buildTestApp();
    const accountKey = `qa-phase6-${randomUUID().slice(0, 8)}`;

    try {
      await reset();

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'QA Phase 6 Tenant',
          accountKey,
        },
      });

      expect(createRes.statusCode).toBe(201);
      const created = readJson<CpAccountDetail>(createRes);

      expect(created.settingsHandoff.mode).toBe('PRODUCER_ONLY');
      expect(created.settingsHandoff.consumer.settingsEnginePresent).toBe(false);
      expect(created.settingsHandoff.consumer.cascadeStatus).toBe('NOT_WIRED');
      expect(created.settingsHandoff.eligibility).toBe('BLOCKED_UNPUBLISHED_ACCOUNT');
      expect(created.settingsHandoff.consumer.blockingReasons).toEqual([
        'Settings Step 10 Phase 2 is not implemented in this repo yet. The Control Plane remains a producer-only source of allowance truth.',
        `Account "${accountKey}" is not provisioned to a tenant yet. Publish the account before any future Settings cascade can become eligible.`,
      ]);
      expect(created.settingsHandoff.account.cpRevision).toBe(0);
      expect(created.settingsHandoff.provisioning.isProvisioned).toBe(false);
      expect(created.settingsHandoff.allowances.access).not.toHaveProperty('configured');
      expect(created.settingsHandoff.allowances.account).not.toHaveProperty('configured');

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
      const integrationsAccount = readJson<CpAccountDetail>(integrationsRes);
      expect(integrationsAccount.cpRevision).toBe(1);
      expect(
        integrationsAccount.settingsHandoff.allowances.integrations.integrations.find(
          (integration) => integration.integrationKey === 'integration.sso.google',
        ),
      ).toMatchObject({
        integrationKey: 'integration.sso.google',
        isAllowed: true,
      });

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
            memberRequired: true,
          },
          signupPolicy: {
            publicSignup: false,
            adminInvitationsAllowed: true,
            allowedDomains: ['example.com', 'Example.com'],
          },
        },
      });

      expect(accessRes.statusCode).toBe(200);
      const accessAccount = readJson<CpAccountDetail>(accessRes);
      expect(accessAccount.cpRevision).toBe(2);
      expect(accessAccount.settingsHandoff.allowances.access).toEqual({
        loginMethods: {
          password: true,
          google: true,
          microsoft: false,
        },
        mfaPolicy: {
          adminRequired: true,
          memberRequired: true,
        },
        signupPolicy: {
          publicSignup: false,
          adminInvitationsAllowed: true,
          allowedDomains: ['example.com'],
        },
      });

      const accountSettingsRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/account-settings`,
        payload: {
          branding: {
            logo: true,
            menuColor: false,
            fontColor: true,
            welcomeMessage: false,
          },
          organizationStructure: {
            employers: true,
            locations: false,
          },
          companyCalendar: {
            allowed: true,
          },
        },
      });

      expect(accountSettingsRes.statusCode).toBe(200);
      const accountSettingsAccount = readJson<CpAccountDetail>(accountSettingsRes);
      expect(accountSettingsAccount.cpRevision).toBe(3);
      expect(accountSettingsAccount.settingsHandoff.allowances.account).toEqual({
        branding: {
          logo: true,
          menuColor: false,
          fontColor: true,
          welcomeMessage: false,
        },
        organizationStructure: {
          employers: true,
          locations: false,
        },
        companyCalendar: {
          allowed: true,
        },
      });

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
      const modulesAccount = readJson<CpAccountDetail>(modulesRes);
      expect(modulesAccount.cpRevision).toBe(4);
      expect(modulesAccount.settingsHandoff.allowances.modules).toEqual({
        modules: {
          personal: false,
          documents: false,
          benefits: false,
          payments: false,
        },
      });

      const publishRes = await app.inject({
        method: 'POST',
        url: `/cp/accounts/${accountKey}/publish`,
        payload: {
          targetStatus: 'Active',
        },
      });

      expect(publishRes.statusCode).toBe(200);
      const published = readJson<CpAccountReview>(publishRes);
      expect(published.account.cpRevision).toBe(4);
      expect(published.account.settingsHandoff.mode).toBe('PRODUCER_ONLY');
      expect(published.account.settingsHandoff.consumer.cascadeStatus).toBe('NOT_WIRED');
      expect(published.account.settingsHandoff.eligibility).toBe(
        'READY_FOR_FUTURE_SETTINGS_CONSUMER',
      );
      expect(published.account.settingsHandoff.consumer.blockingReasons).toEqual([
        'Settings Step 10 Phase 2 is not implemented in this repo yet. The Control Plane remains a producer-only source of allowance truth.',
      ]);
      expect(published.account.settingsHandoff.provisioning).toMatchObject({
        isProvisioned: true,
        tenantKey: accountKey,
        tenantName: 'QA Phase 6 Tenant',
        tenantState: 'ACTIVE',
      });

      const internalHandoff =
        await deps.controlPlane.accounts.cpAccountsService.getSettingsHandoff(accountKey);

      expect(internalHandoff.contractVersion).toBe(1);
      expect(internalHandoff.producedAt).toBeInstanceOf(Date);
      expect(internalHandoff.mode).toBe('PRODUCER_ONLY');
      expect(internalHandoff.eligibility).toBe('READY_FOR_FUTURE_SETTINGS_CONSUMER');
      expect(internalHandoff.consumer).toEqual({
        settingsEnginePresent: false,
        cascadeStatus: 'NOT_WIRED',
        blockingReasons: [
          'Settings Step 10 Phase 2 is not implemented in this repo yet. The Control Plane remains a producer-only source of allowance truth.',
        ],
      });
      expect(internalHandoff.account).toEqual({
        accountId: created.id,
        accountKey,
        accountName: 'QA Phase 6 Tenant',
        cpStatus: 'Active',
        cpRevision: 4,
      });
      expect(internalHandoff.provisioning.isProvisioned).toBe(true);
      expect(internalHandoff.provisioning.tenantId).toBe(published.provisioning.tenantId);
      expect(internalHandoff.provisioning.tenantKey).toBe(accountKey);
      expect(internalHandoff.provisioning.tenantName).toBe('QA Phase 6 Tenant');
      expect(internalHandoff.provisioning.tenantState).toBe('ACTIVE');
      expect(internalHandoff.provisioning.publishedAt).toBeInstanceOf(Date);
      expect(internalHandoff.allowances.access).toEqual({
        loginMethods: {
          password: true,
          google: true,
          microsoft: false,
        },
        mfaPolicy: {
          adminRequired: true,
          memberRequired: true,
        },
        signupPolicy: {
          publicSignup: false,
          adminInvitationsAllowed: true,
          allowedDomains: ['example.com'],
        },
      });
    } finally {
      await close();
    }
  });
});
