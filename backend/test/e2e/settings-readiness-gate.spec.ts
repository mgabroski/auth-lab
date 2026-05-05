import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';
import {
  createPublishedSettingsTenant,
  createSettingsAdmin,
  getSettingsBootstrap,
  hostForTenant,
  readJson,
} from '../helpers/settings-fixtures';
import type { ConfigResponse } from '../../src/modules/auth/auth.types';
import type { SettingsBootstrapDto } from '../../src/modules/settings/settings.types';

describe('settings readiness gate', () => {
  it('keeps Settings bootstrap authoritative even when retired auth compatibility metadata exists', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-ready-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      const tenant = await createPublishedSettingsTenant({ app, deps, accountKey });
      const admin = await createSettingsAdmin({
        app,
        deps,
        tenant,
        email: `settings-ready-admin-${randomUUID().slice(0, 8)}@example.com`,
      });

      await deps.db
        .updateTable('tenants')
        .set({ setup_completed_at: new Date('2026-05-05T10:00:00.000Z') })
        .where('id', '=', tenant.tenantId)
        .execute();

      const authConfigRes = await app.inject({
        method: 'GET',
        url: '/auth/config',
        headers: { host: hostForTenant(tenant.tenantKey) },
      });
      expect(authConfigRes.statusCode).toBe(200);
      expect(readJson<ConfigResponse>(authConfigRes).tenant.setupCompleted).toBe(true);

      const settingsBootstrap = await getSettingsBootstrap({
        app,
        tenantKey: tenant.tenantKey,
        cookie: admin.cookie,
      });

      expect(settingsBootstrap).toEqual({
        overallStatus: 'NOT_STARTED',
        showSetupBanner: true,
        nextAction: {
          key: 'access',
          label: 'Review Access & Security',
          href: '/admin/settings/access',
        },
      } satisfies SettingsBootstrapDto);
    } finally {
      await close();
    }
  });

  it('rejects the retired auth acknowledgement route without changing native Settings state', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `settings-ack-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      const tenant = await createPublishedSettingsTenant({ app, deps, accountKey });
      const admin = await createSettingsAdmin({
        app,
        deps,
        tenant,
        email: `settings-ack-admin-${randomUUID().slice(0, 8)}@example.com`,
      });

      const before = await deps.settings.foundationRepo.getStateBundle(tenant.tenantId);
      expect(before).toBeDefined();

      const retiredAckRes = await app.inject({
        method: 'POST',
        url: '/auth/workspace-setup-ack',
        headers: { host: hostForTenant(tenant.tenantKey), cookie: admin.cookie },
      });
      expect(retiredAckRes.statusCode).toBe(404);

      const tenantRow = await deps.db
        .selectFrom('tenants')
        .select(['setup_completed_at'])
        .where('id', '=', tenant.tenantId)
        .executeTakeFirstOrThrow();
      expect(tenantRow.setup_completed_at).toBeNull();

      const after = await deps.settings.foundationRepo.getStateBundle(tenant.tenantId);
      expect(after).toBeDefined();
      expect(after?.aggregate).toMatchObject({
        overallStatus: before?.aggregate.overallStatus,
        version: before?.aggregate.version,
        appliedCpRevision: before?.aggregate.appliedCpRevision,
      });
      expect(after?.sections.access).toMatchObject({
        status: before?.sections.access.status,
        version: before?.sections.access.version,
        appliedCpRevision: before?.sections.access.appliedCpRevision,
      });
    } finally {
      await close();
    }
  });
});
