import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import type { ConfigResponse } from '../../src/modules/auth/auth.types';

type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
  };
};
import type { CpAccountReview } from '../../src/modules/control-plane/accounts/cp-accounts.types';
import { buildTestApp } from '../helpers/build-test-app';

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

describe('cp accounts review & publish', () => {
  it('blocks Active publish until Activation Ready passes, but provisions Disabled', async () => {
    const { app, close, reset } = await buildTestApp();
    const accountKey = `qa-phase4-${randomUUID().slice(0, 8)}`;

    try {
      await reset();

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'QA Phase 4 Tenant',
          accountKey,
        },
      });

      expect(createRes.statusCode).toBe(201);

      const reviewRes = await app.inject({
        method: 'GET',
        url: `/cp/accounts/${accountKey}/review`,
      });

      expect(reviewRes.statusCode).toBe(200);
      const review = readJson<CpAccountReview>(reviewRes);
      expect(review.activationReadiness.isReady).toBe(false);

      const publishActiveRes = await app.inject({
        method: 'POST',
        url: `/cp/accounts/${accountKey}/publish`,
        payload: {
          targetStatus: 'Active',
        },
      });

      expect(publishActiveRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(publishActiveRes)).toEqual({
        error: {
          code: 'CONFLICT',
          message: 'Active publish is blocked until Activation Ready passes.',
        },
      });

      const publishDisabledRes = await app.inject({
        method: 'POST',
        url: `/cp/accounts/${accountKey}/publish`,
        payload: {
          targetStatus: 'Disabled',
        },
      });

      expect(publishDisabledRes.statusCode).toBe(200);
      const disabledReview = readJson<CpAccountReview>(publishDisabledRes);

      expect(disabledReview.account.cpStatus).toBe('Disabled');
      expect(disabledReview.provisioning.isProvisioned).toBe(true);
      expect(disabledReview.provisioning.tenantKey).toBe(accountKey);
      expect(disabledReview.provisioning.tenantState).toBe('DISABLED');

      const inactiveConfigRes = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: {
          host: hostForTenant(accountKey),
        },
      });

      expect(inactiveConfigRes.statusCode).toBe(200);
      expect(readJson<ConfigResponse>(inactiveConfigRes)).toEqual({
        tenant: {
          name: '',
          isActive: false,
          publicSignupEnabled: false,
          signupAllowed: false,
          allowedSso: [],
          setupCompleted: false,
        },
      });

      const accessRes = await app.inject({
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

      const settingsRes = await app.inject({
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

      expect(settingsRes.statusCode).toBe(200);

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

      const publishActiveRes2 = await app.inject({
        method: 'POST',
        url: `/cp/accounts/${accountKey}/publish`,
        payload: {
          targetStatus: 'Active',
        },
      });

      expect(publishActiveRes2.statusCode).toBe(200);
      const activeReview = readJson<CpAccountReview>(publishActiveRes2);

      expect(activeReview.activationReadiness.isReady).toBe(true);
      expect(activeReview.account.cpStatus).toBe('Active');
      expect(activeReview.provisioning.tenantState).toBe('ACTIVE');

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
          name: 'QA Phase 4 Tenant',
          isActive: true,
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
