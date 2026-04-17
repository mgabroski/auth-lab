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

function buildValidIntegrationsPayload(): SaveCpIntegrationsInput {
  return {
    integrations: INTEGRATION_CATALOG.map((integration) => ({
      integrationKey: integration.integrationKey,
      isAllowed: integration.defaultAllowed,
      capabilities: integration.capabilities.map((capability) => ({
        capabilityKey: capability.capabilityKey,
        isAllowed: capability.defaultAllowed,
      })),
    })),
  };
}

describe('cp accounts audit coverage', () => {
  it('writes success audits for Step 2 saves and durable failure audits outside rollback', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `qa-audit-${randomUUID().slice(0, 8)}`;

    try {
      await reset();

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'QA Audit Tenant',
          accountKey,
        },
      });

      expect(createRes.statusCode).toBe(201);

      const duplicateCreateRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'QA Audit Tenant Duplicate',
          accountKey,
        },
      });

      expect(duplicateCreateRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(duplicateCreateRes).error.code).toBe('CONFLICT');

      const failingAccessRes = await app.inject({
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

      expect(failingAccessRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(failingAccessRes).error.message).toContain(
        'Google login method requires the Google SSO integration allowance to be saved first.',
      );

      const draftStatusToggleRes = await app.inject({
        method: 'PATCH',
        url: `/cp/accounts/${accountKey}/status`,
        payload: {
          targetStatus: 'Disabled',
        },
      });

      expect(draftStatusToggleRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(draftStatusToggleRes).error.code).toBe('CONFLICT');

      expect(
        (
          await app.inject({
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
                documents: false,
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
            payload: buildValidIntegrationsPayload(),
          })
        ).statusCode,
      ).toBe(200);

      expect(
        (
          await app.inject({
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
          })
        ).statusCode,
      ).toBe(200);

      const audits = await deps.db
        .selectFrom('audit_events')
        .select(['action', 'metadata'])
        .where('action', 'like', 'cp.account.%')
        .orderBy('created_at asc')
        .execute();

      expect(audits.map((audit) => audit.action)).toEqual([
        'cp.account.created',
        'cp.account.create.failed',
        'cp.account.access.save.failed',
        'cp.account.status_toggle.failed',
        'cp.account.account_settings.saved',
        'cp.account.modules.saved',
        'cp.account.personal.saved',
        'cp.account.integrations.saved',
        'cp.account.access.saved',
      ]);

      const duplicateCreateFailure = audits[1].metadata as Record<string, unknown>;
      expect(duplicateCreateFailure.accountKey).toBe(accountKey);
      expect(duplicateCreateFailure.accountId).toBeTypeOf('string');
      expect(duplicateCreateFailure.errorCode).toBe('CONFLICT');

      const accessFailure = audits[2].metadata as Record<string, unknown>;
      expect(accessFailure.accountKey).toBe(accountKey);
      expect(accessFailure.accountId).toBeTypeOf('string');
      expect(accessFailure.errorCode).toBe('CONFLICT');

      const draftStatusFailure = audits[3].metadata as Record<string, unknown>;
      expect(draftStatusFailure.accountKey).toBe(accountKey);
      expect(draftStatusFailure.accountId).toBeTypeOf('string');
      expect(draftStatusFailure.errorCode).toBe('CONFLICT');

      const accountSettingsSaved = audits[4].metadata as Record<string, unknown>;
      expect(accountSettingsSaved.accountKey).toBe(accountKey);
      expect(accountSettingsSaved.changed).toBe(true);
      expect(accountSettingsSaved.cpRevision).toBe(1);

      const moduleSettingsSaved = audits[5].metadata as Record<string, unknown>;
      expect(moduleSettingsSaved.changed).toBe(true);
      expect(moduleSettingsSaved.cpRevision).toBe(2);

      const personalSaved = audits[6].metadata as Record<string, unknown>;
      expect(personalSaved.changed).toBe(true);
      expect(personalSaved.cpRevision).toBe(3);

      const integrationsSaved = audits[7].metadata as Record<string, unknown>;
      expect(integrationsSaved.changed).toBe(true);
      expect(integrationsSaved.cpRevision).toBe(4);

      const accessSaved = audits[8].metadata as Record<string, unknown>;
      expect(accessSaved.accountKey).toBe(accountKey);
      expect(accessSaved.changed).toBe(true);
      expect(accessSaved.cpRevision).toBe(5);
    } finally {
      await close();
    }
  });
});
