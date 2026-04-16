import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import type { ConfigResponse } from '../../src/modules/auth/auth.types';
import type {
  CpAccountDetail,
  CpAccountListRow,
} from '../../src/modules/control-plane/accounts/cp-accounts.types';
import { buildTestApp } from '../helpers/build-test-app';

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

describe('cp accounts edit / re-entry / status toggle', () => {
  it('supports real re-entry, real Active/Disabled toggle, and honest cpRevision behavior', async () => {
    const { app, close, reset } = await buildTestApp();
    const accountKey = `qa-phase5-${randomUUID().slice(0, 8)}`;

    try {
      await reset();

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'QA Phase 5 Tenant',
          accountKey,
        },
      });

      expect(createRes.statusCode).toBe(201);
      const created = readJson<CpAccountDetail>(createRes);
      expect(created.cpStatus).toBe('Draft');
      expect(created.cpRevision).toBe(0);

      const draftToggleRes = await app.inject({
        method: 'PATCH',
        url: `/cp/accounts/${accountKey}/status`,
        payload: {
          targetStatus: 'Disabled',
        },
      });

      expect(draftToggleRes.statusCode).toBe(409);

      const accessPayload = {
        loginMethods: {
          password: true,
          google: false,
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
      };

      const accessRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: accessPayload,
      });

      expect(accessRes.statusCode).toBe(200);
      const accessAccount = readJson<CpAccountDetail>(accessRes);
      expect(accessAccount.cpRevision).toBe(1);
      expect(accessAccount.access.configured).toBe(true);

      const accessNoOpRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: accessPayload,
      });

      expect(accessNoOpRes.statusCode).toBe(200);
      const accessNoOpAccount = readJson<CpAccountDetail>(accessNoOpRes);
      expect(accessNoOpAccount.cpRevision).toBe(1);

      const accountSettingsRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/account-settings`,
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
      const accountSettingsAccount = readJson<CpAccountDetail>(accountSettingsRes);
      expect(accountSettingsAccount.cpRevision).toBe(2);
      expect(accountSettingsAccount.accountSettings.configured).toBe(true);

      const moduleRes = await app.inject({
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

      expect(moduleRes.statusCode).toBe(200);
      const moduleAccount = readJson<CpAccountDetail>(moduleRes);
      expect(moduleAccount.cpRevision).toBe(3);
      expect(moduleAccount.moduleSettings.configured).toBe(true);
      expect(moduleAccount.step2Progress.canContinueToReview).toBe(true);

      const detailRes = await app.inject({
        method: 'GET',
        url: `/cp/accounts/${accountKey}`,
      });

      expect(detailRes.statusCode).toBe(200);
      const detail = readJson<CpAccountDetail>(detailRes);
      expect(detail.accountName).toBe('QA Phase 5 Tenant');
      expect(detail.access.configured).toBe(true);
      expect(detail.accountSettings.configured).toBe(true);
      expect(detail.moduleSettings.configured).toBe(true);
      expect(detail.cpStatus).toBe('Draft');
      expect(detail.cpRevision).toBe(3);

      const publishDisabledRes = await app.inject({
        method: 'POST',
        url: `/cp/accounts/${accountKey}/publish`,
        payload: {
          targetStatus: 'Disabled',
        },
      });

      expect(publishDisabledRes.statusCode).toBe(200);
      const disabledAfterPublish = readJson<{ account: CpAccountDetail }>(publishDisabledRes);
      expect(disabledAfterPublish.account.cpStatus).toBe('Disabled');
      expect(disabledAfterPublish.account.cpRevision).toBe(3);

      const listAfterPublishRes = await app.inject({
        method: 'GET',
        url: '/cp/accounts',
      });

      expect(listAfterPublishRes.statusCode).toBe(200);
      const listAfterPublish = readJson<{ accounts: CpAccountListRow[] }>(listAfterPublishRes);
      const publishedRow = listAfterPublish.accounts.find((row) => row.accountKey === accountKey);
      expect(publishedRow?.cpStatus).toBe('Disabled');
      expect(publishedRow?.step2Progress.canContinueToReview).toBe(true);

      const activateRes = await app.inject({
        method: 'PATCH',
        url: `/cp/accounts/${accountKey}/status`,
        payload: {
          targetStatus: 'Active',
        },
      });

      expect(activateRes.statusCode).toBe(200);
      const activated = readJson<CpAccountDetail>(activateRes);
      expect(activated.cpStatus).toBe('Active');
      expect(activated.cpRevision).toBe(3);

      const activeConfigRes = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: {
          host: hostForTenant(accountKey),
        },
      });

      expect(activeConfigRes.statusCode).toBe(200);
      expect(readJson<ConfigResponse>(activeConfigRes)).toEqual({
        tenant: {
          name: 'QA Phase 5 Tenant',
          isActive: true,
          publicSignupEnabled: false,
          signupAllowed: false,
          allowedSso: [],
          setupCompleted: false,
        },
      });

      const disableAgainRes = await app.inject({
        method: 'PATCH',
        url: `/cp/accounts/${accountKey}/status`,
        payload: {
          targetStatus: 'Disabled',
        },
      });

      expect(disableAgainRes.statusCode).toBe(200);
      const disabledAgain = readJson<CpAccountDetail>(disableAgainRes);
      expect(disabledAgain.cpStatus).toBe('Disabled');
      expect(disabledAgain.cpRevision).toBe(3);

      const disabledNoOpRes = await app.inject({
        method: 'PATCH',
        url: `/cp/accounts/${accountKey}/status`,
        payload: {
          targetStatus: 'Disabled',
        },
      });

      expect(disabledNoOpRes.statusCode).toBe(200);
      const disabledNoOp = readJson<CpAccountDetail>(disabledNoOpRes);
      expect(disabledNoOp.cpStatus).toBe('Disabled');
      expect(disabledNoOp.cpRevision).toBe(3);

      const disabledConfigRes = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: {
          host: hostForTenant(accountKey),
        },
      });

      expect(disabledConfigRes.statusCode).toBe(200);
      expect(readJson<ConfigResponse>(disabledConfigRes)).toEqual({
        tenant: {
          name: '',
          isActive: false,
          publicSignupEnabled: false,
          signupAllowed: false,
          allowedSso: [],
          setupCompleted: false,
        },
      });
    } finally {
      await close();
    }
  });
});
