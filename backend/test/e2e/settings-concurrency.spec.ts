import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

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

describe('settings concurrent mutation proof', () => {
  it('allows only one concurrent Account card save for the same card version', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-concurrent-account-${randomUUID().slice(0, 8)}`;

    try {
      await reset();

      const tenant = await createPublishedSettingsTenant({
        app,
        deps,
        accountKey,
        personalEnabled: false,
      });
      const admin = await createSettingsAdmin({
        app,
        deps,
        tenant,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
      });

      const account = await getAccountSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      const branding = account.cards.find((card) => card.key === 'branding');
      if (!branding || branding.key !== 'branding') {
        throw new Error('Expected Branding card in concurrent Account proof');
      }

      const makeRequest = (label: 'A' | 'B') =>
        app.inject({
          method: 'PUT',
          url: '/settings/account/branding',
          headers: {
            host: hostForTenant(tenant.tenantKey),
            cookie: admin.cookie,
          },
          payload: {
            expectedVersion: branding.version,
            expectedCpRevision: branding.cpRevision,
            values: {
              logoUrl: `https://cdn.example.com/concurrent-${label.toLowerCase()}.svg`,
              menuColor: label === 'A' ? '#0f172a' : '#111827',
              fontColor: '#ffffff',
              welcomeMessage: `Concurrent ${label} saved`,
            },
          },
        });

      const [first, second] = await Promise.all([makeRequest('A'), makeRequest('B')]);
      const results = [
        { label: 'A' as const, res: first },
        { label: 'B' as const, res: second },
      ];
      const statusCodes = results.map((result) => result.res.statusCode).sort((a, b) => a - b);

      expect(statusCodes).toEqual([200, 409]);

      const failed = results.find((result) => result.res.statusCode === 409);
      expect(failed).toBeDefined();
      const failureBody = readJson<ErrorResponseBody>(failed!.res);
      expect(failureBody.error.code).toBe('CONFLICT');
      expect(failureBody.error.message).toContain('Branding changed while you were editing it');

      const winner = results.find((result) => result.res.statusCode === 200);
      expect(winner).toBeDefined();

      const after = await getAccountSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      const savedBranding = after.cards.find((card) => card.key === 'branding');
      if (!savedBranding || savedBranding.key !== 'branding') {
        throw new Error('Expected saved Branding card after concurrent Account proof');
      }

      expect(savedBranding.version).toBe(branding.version + 1);
      expect(savedBranding.values.welcomeMessage).toBe(`Concurrent ${winner!.label} saved`);
    } finally {
      await close();
    }
  });

  it('allows only one concurrent Personal full-replacement save for the same section version', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-concurrent-personal-${randomUUID().slice(0, 8)}`;

    try {
      await reset();

      const tenant = await createPublishedSettingsTenant({
        app,
        deps,
        accountKey,
        personalEnabled: true,
      });
      const admin = await createSettingsAdmin({
        app,
        deps,
        tenant,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
      });

      const personal = await getPersonalSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });
      const basePayload = buildPersonalSavePayload(personal);

      const makePayload = (label: 'A' | 'B') => ({
        ...basePayload,
        sections: basePayload.sections.map((section, index) =>
          index === 0 ? { ...section, name: `Concurrent ${label} Personal` } : section,
        ),
      });

      const makeRequest = (label: 'A' | 'B') =>
        app.inject({
          method: 'PUT',
          url: '/settings/modules/personal',
          headers: {
            host: hostForTenant(tenant.tenantKey),
            cookie: admin.cookie,
          },
          payload: makePayload(label),
        });

      const [first, second] = await Promise.all([makeRequest('A'), makeRequest('B')]);
      const results = [
        { label: 'A' as const, res: first },
        { label: 'B' as const, res: second },
      ];
      const statusCodes = results.map((result) => result.res.statusCode).sort((a, b) => a - b);

      expect(statusCodes).toEqual([200, 409]);

      const failed = results.find((result) => result.res.statusCode === 409);
      expect(failed).toBeDefined();
      const failureBody = readJson<ErrorResponseBody>(failed!.res);
      expect(failureBody.error.code).toBe('CONFLICT');
      expect(failureBody.error.message).toContain(
        'Personal settings changed while you were editing them',
      );

      const winner = results.find((result) => result.res.statusCode === 200);
      expect(winner).toBeDefined();

      const after = await getPersonalSettings({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });

      expect(after.version).toBe(personal.version + 1);
      expect(after.status).toBe('COMPLETE');
      expect(after.sectionBuilder.sections[0]?.name).toBe(`Concurrent ${winner!.label} Personal`);
    } finally {
      await close();
    }
  });
});
