import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import type { CpAccountDetail } from '../../src/modules/control-plane/accounts/cp-accounts.types';
import { buildTestApp } from '../helpers/build-test-app';

type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
  };
};

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function buildIntegrationsPayload(account: CpAccountDetail, overrides: Record<string, boolean>) {
  return {
    integrations: account.integrations.integrations.map((integration) => ({
      integrationKey: integration.integrationKey,
      isAllowed: overrides[integration.integrationKey] ?? integration.isAllowed,
      capabilities: integration.capabilities.map((capability) => ({
        capabilityKey: capability.capabilityKey,
        isAllowed:
          overrides[capability.capabilityKey] ??
          ((overrides[integration.integrationKey] ?? integration.isAllowed)
            ? capability.isAllowed
            : false),
      })),
    })),
  };
}

describe('cp accounts dependency guards', () => {
  it('blocks Google and Microsoft login methods until their matching SSO integrations are allowed', async () => {
    const { app, close, reset } = await buildTestApp();
    const accountKey = `qa-cp-deps-${randomUUID().slice(0, 8)}`;

    try {
      await reset();

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'QA CP Dependency Tenant',
          accountKey,
        },
      });

      expect(createRes.statusCode).toBe(201);
      const created = readJson<CpAccountDetail>(createRes);

      const googleBlockedRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: {
          loginMethods: {
            password: false,
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

      expect(googleBlockedRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(googleBlockedRes)).toEqual({
        error: {
          code: 'CONFLICT',
          message:
            'Google login method requires the Google SSO integration allowance to be saved first.',
        },
      });

      const integrationsRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/integrations`,
        payload: buildIntegrationsPayload(created, {
          'integration.sso.google': true,
        }),
      });

      expect(integrationsRes.statusCode).toBe(200);

      const googleAccessRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: {
          loginMethods: {
            password: false,
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

      expect(googleAccessRes.statusCode).toBe(200);

      const microsoftBlockedRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: {
          loginMethods: {
            password: false,
            google: true,
            microsoft: true,
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

      expect(microsoftBlockedRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(microsoftBlockedRes)).toEqual({
        error: {
          code: 'CONFLICT',
          message:
            'Microsoft login method requires the Microsoft SSO integration allowance to be saved first.',
        },
      });
    } finally {
      await close();
    }
  });

  it('blocks disabling a required SSO integration while the dependent login method is still enabled', async () => {
    const { app, close, reset } = await buildTestApp();
    const accountKey = `qa-cp-integration-${randomUUID().slice(0, 8)}`;

    try {
      await reset();

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'QA CP Integration Tenant',
          accountKey,
        },
      });

      expect(createRes.statusCode).toBe(201);
      const created = readJson<CpAccountDetail>(createRes);

      const allowGoogleIntegrationRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/integrations`,
        payload: buildIntegrationsPayload(created, {
          'integration.sso.google': true,
        }),
      });

      expect(allowGoogleIntegrationRes.statusCode).toBe(200);
      const withGoogleIntegration = readJson<CpAccountDetail>(allowGoogleIntegrationRes);

      const saveAccessRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: {
          loginMethods: {
            password: false,
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

      expect(saveAccessRes.statusCode).toBe(200);

      const disableGoogleIntegrationRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/integrations`,
        payload: buildIntegrationsPayload(withGoogleIntegration, {
          'integration.sso.google': false,
        }),
      });

      expect(disableGoogleIntegrationRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(disableGoogleIntegrationRes)).toEqual({
        error: {
          code: 'CONFLICT',
          message:
            'Google SSO integration cannot be disabled while Google login method remains enabled in Access, Identity & Security.',
        },
      });
    } finally {
      await close();
    }
  });

  it('blocks disabling Microsoft SSO while Microsoft login method is still enabled', async () => {
    const { app, close, reset } = await buildTestApp();
    const accountKey = `qa-cp-microsoft-${randomUUID().slice(0, 8)}`;

    try {
      await reset();

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'QA CP Microsoft Integration Tenant',
          accountKey,
        },
      });

      expect(createRes.statusCode).toBe(201);
      const created = readJson<CpAccountDetail>(createRes);

      const allowMicrosoftIntegrationRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/integrations`,
        payload: buildIntegrationsPayload(created, {
          'integration.sso.microsoft': true,
        }),
      });

      expect(allowMicrosoftIntegrationRes.statusCode).toBe(200);
      const withMicrosoftIntegration = readJson<CpAccountDetail>(allowMicrosoftIntegrationRes);

      const saveAccessRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: {
          loginMethods: {
            password: false,
            google: false,
            microsoft: true,
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

      expect(saveAccessRes.statusCode).toBe(200);

      const disableMicrosoftIntegrationRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/integrations`,
        payload: buildIntegrationsPayload(withMicrosoftIntegration, {
          'integration.sso.microsoft': false,
        }),
      });

      expect(disableMicrosoftIntegrationRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(disableMicrosoftIntegrationRes)).toEqual({
        error: {
          code: 'CONFLICT',
          message:
            'Microsoft SSO integration cannot be disabled while Microsoft login method remains enabled in Access, Identity & Security.',
        },
      });
    } finally {
      await close();
    }
  });
});
