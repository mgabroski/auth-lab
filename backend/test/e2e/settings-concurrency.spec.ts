import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import type {
  AccountSettingsDto,
  PersonalSettingsDto,
  SettingsMutationResponse,
} from '../../src/modules/settings/settings.types';
import { buildTestApp } from '../helpers/build-test-app';
import {
  buildPersonalSavePayload,
  createPublishedSettingsTenant,
  createSettingsAdmin,
  getAccountSettings,
  getPersonalSettings,
  hostForTenant,
  readJson,
} from '../helpers/settings-fixtures';

type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
  };
};

type AccountCard = AccountSettingsDto['cards'][number];

function findAccountCard<K extends AccountCard['key']>(
  account: AccountSettingsDto,
  key: K,
): Extract<AccountCard, { key: K }> {
  const card = account.cards.find((candidate) => candidate.key === key);
  if (!card || card.key !== key) {
    throw new Error(`Expected Account card ${key}`);
  }
  return card as Extract<AccountCard, { key: K }>;
}

function personalPayloadFrom(personal: PersonalSettingsDto) {
  return buildPersonalSavePayload(personal);
}

describe('settings concurrent mutation proof', () => {
  it('allows only one concurrent Account save for the same card version', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-account-race-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      const tenant = await createPublishedSettingsTenant({ app, deps, accountKey });
      const admin = await createSettingsAdmin({
        app,
        deps,
        tenant,
        email: `settings-account-race-${randomUUID().slice(0, 8)}@example.com`,
      });

      const account = await getAccountSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      const branding = findAccountCard(account, 'branding');

      const requestA = app.inject({
        method: 'PUT',
        url: '/settings/account/branding',
        headers: { host: hostForTenant(tenant.tenantKey), cookie: admin.cookie },
        payload: {
          expectedVersion: branding.version,
          expectedCpRevision: branding.cpRevision,
          values: {
            logoUrl: 'https://cdn.example.com/logo-a.svg',
            menuColor: '#0f172a',
            fontColor: '#ffffff',
            welcomeMessage: 'Concurrent save A',
          },
        },
      });

      const requestB = app.inject({
        method: 'PUT',
        url: '/settings/account/branding',
        headers: { host: hostForTenant(tenant.tenantKey), cookie: admin.cookie },
        payload: {
          expectedVersion: branding.version,
          expectedCpRevision: branding.cpRevision,
          values: {
            logoUrl: 'https://cdn.example.com/logo-b.svg',
            menuColor: '#111827',
            fontColor: '#f8fafc',
            welcomeMessage: 'Concurrent save B',
          },
        },
      });

      const results = await Promise.all([requestA, requestB]);
      const statusCodes = results.map((result) => result.statusCode).sort((a, b) => a - b);
      expect(statusCodes).toEqual([200, 409]);

      const failed = results.find((result) => result.statusCode === 409);
      expect(failed).toBeDefined();
      expect(readJson<ErrorResponseBody>(failed!).error.message).toContain(
        'Branding changed while you were editing it',
      );

      const after = await getAccountSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      const afterBranding = findAccountCard(after, 'branding');
      expect(afterBranding.version).toBe(2);
      expect(afterBranding.status).toBe('COMPLETE');
    } finally {
      await close();
    }
  });

  it('serializes valid concurrent Account saves to different cards without losing either write', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-account-cross-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      const tenant = await createPublishedSettingsTenant({ app, deps, accountKey });
      const admin = await createSettingsAdmin({
        app,
        deps,
        tenant,
        email: `settings-account-cross-${randomUUID().slice(0, 8)}@example.com`,
      });

      const before = await getAccountSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      const branding = findAccountCard(before, 'branding');
      const orgStructure = findAccountCard(before, 'orgStructure');
      const beforeState = await deps.settings.foundationRepo.getStateBundle(tenant.tenantId);
      expect(beforeState?.sections.account.version).toBe(1);

      const brandingRequest = app.inject({
        method: 'PUT',
        url: '/settings/account/branding',
        headers: { host: hostForTenant(tenant.tenantKey), cookie: admin.cookie },
        payload: {
          expectedVersion: branding.version,
          expectedCpRevision: branding.cpRevision,
          values: {
            logoUrl: 'https://cdn.example.com/cross-card.svg',
            menuColor: '#0f172a',
            fontColor: '#ffffff',
            welcomeMessage: 'Branding saved in a cross-card race.',
          },
        },
      });

      const orgRequest = app.inject({
        method: 'PUT',
        url: '/settings/account/org-structure',
        headers: { host: hostForTenant(tenant.tenantKey), cookie: admin.cookie },
        payload: {
          expectedVersion: orgStructure.version,
          expectedCpRevision: orgStructure.cpRevision,
          values: {
            employers: ['North Terminal'],
            locations: ['Denver Yard'],
          },
        },
      });

      const results = await Promise.all([brandingRequest, orgRequest]);
      expect(results.map((result) => result.statusCode).sort((a, b) => a - b)).toEqual([200, 200]);

      const after = await getAccountSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      const afterBranding = findAccountCard(after, 'branding');
      const afterOrgStructure = findAccountCard(after, 'orgStructure');
      expect(afterBranding.version).toBe(2);
      expect(afterBranding.status).toBe('COMPLETE');
      expect(afterOrgStructure.version).toBe(2);
      expect(afterOrgStructure.status).toBe('COMPLETE');
      expect(afterOrgStructure.values).toEqual({
        employers: ['North Terminal'],
        locations: ['Denver Yard'],
      });

      const afterState = await deps.settings.foundationRepo.getStateBundle(tenant.tenantId);
      expect(afterState?.sections.account.status).toBe('IN_PROGRESS');
      expect(afterState?.sections.account.version).toBe(3);
    } finally {
      await close();
    }
  });

  it('allows only one concurrent Personal full-replacement save for the same section version', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-personal-race-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      const tenant = await createPublishedSettingsTenant({ app, deps, accountKey });
      const admin = await createSettingsAdmin({
        app,
        deps,
        tenant,
        email: `settings-personal-race-${randomUUID().slice(0, 8)}@example.com`,
      });

      const personal = await getPersonalSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      const payloadA = personalPayloadFrom(personal);
      const payloadB = personalPayloadFrom(personal);
      payloadB.sections = payloadB.sections.map((section, index) =>
        index === 0 ? { ...section, name: `${section.name} Reviewed` } : section,
      );

      const requestA = app.inject({
        method: 'PUT',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.tenantKey), cookie: admin.cookie },
        payload: payloadA,
      });
      const requestB = app.inject({
        method: 'PUT',
        url: '/settings/modules/personal',
        headers: { host: hostForTenant(tenant.tenantKey), cookie: admin.cookie },
        payload: payloadB,
      });

      const results = await Promise.all([requestA, requestB]);
      const statusCodes = results.map((result) => result.statusCode).sort((a, b) => a - b);
      expect(statusCodes).toEqual([200, 409]);

      const failed = results.find((result) => result.statusCode === 409);
      expect(failed).toBeDefined();
      expect(readJson<ErrorResponseBody>(failed!).error.message).toContain(
        'Personal settings changed while you were editing them',
      );

      const successful = results.find((result) => result.statusCode === 200);
      expect(successful).toBeDefined();
      const mutation = readJson<SettingsMutationResponse>(successful!);
      expect(mutation.section).toEqual(
        expect.objectContaining({ key: 'personal', status: 'COMPLETE', version: 2 }),
      );
    } finally {
      await close();
    }
  });
});
