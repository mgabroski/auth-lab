import { describe, it, expect } from 'vitest';
import { buildTestApp } from '../helpers/build-test-app';
import { runDevSeed } from '../../src/shared/db/seed/dev-seed';

describe('dev seed', () => {
  it('is idempotent (tenant + admin invite)', async () => {
    const tenantKey = 'goodwill-ca';
    const adminEmail = 'system_admin@example.com';

    const { deps, close } = await buildTestApp();

    try {
      await runDevSeed({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        options: {
          tenantKey,
          tenantName: 'GoodWill California',
          adminEmail,
          inviteTtlHours: 24 * 7,
        },
      });

      await runDevSeed({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        options: {
          tenantKey,
          tenantName: 'GoodWill California',
          adminEmail,
          inviteTtlHours: 24 * 7,
        },
      });

      const tenants = await deps.db
        .selectFrom('tenants')
        .select(['id', 'key'])
        .where('key', '=', tenantKey)
        .execute();

      expect(tenants).toHaveLength(1);
      const tenantId = tenants[0].id;

      const invites = await deps.db
        .selectFrom('invites')
        .select(['id', 'status', 'role', 'email', 'tenant_id'])
        .where('tenant_id', '=', tenantId)
        .where('email', '=', adminEmail.toLowerCase())
        .where('role', '=', 'ADMIN')
        .execute();

      expect(invites).toHaveLength(1);
      expect(invites[0].status).toBe('PENDING');
    } finally {
      await close();
    }
  });
});
