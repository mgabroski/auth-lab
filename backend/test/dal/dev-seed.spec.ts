import { describe, it, expect } from 'vitest';
import { buildTestApp } from '../helpers/build-test-app';
import { runDevSeed } from '../../src/shared/db/seed/dev-seed';

describe('dev seed', () => {
  it('is idempotent for the canonical auth fixtures', async () => {
    const tenantKey = 'goodwill-ca';
    const adminEmail = 'system_admin@example.com';

    const { deps, close } = await buildTestApp();

    try {
      await runDevSeed({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        passwordHasher: deps.passwordHasher,
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
        passwordHasher: deps.passwordHasher,
        options: {
          tenantKey,
          tenantName: 'GoodWill California',
          adminEmail,
          inviteTtlHours: 24 * 7,
        },
      });

      const tenants = await deps.db
        .selectFrom('tenants')
        .select(['id', 'key', 'public_signup_enabled'])
        .where('key', 'in', ['goodwill-ca', 'goodwill-open'])
        .orderBy('key', 'asc')
        .execute();

      expect(tenants).toHaveLength(2);
      expect(tenants[0]).toMatchObject({ key: 'goodwill-ca', public_signup_enabled: false });
      expect(tenants[1]).toMatchObject({ key: 'goodwill-open', public_signup_enabled: true });

      const bootstrapTenantId = tenants.find((tenant) => tenant.key === tenantKey)!.id;

      const invites = await deps.db
        .selectFrom('invites')
        .select(['id', 'status', 'role', 'email', 'tenant_id'])
        .where('tenant_id', '=', bootstrapTenantId)
        .where('email', '=', adminEmail.toLowerCase())
        .where('role', '=', 'ADMIN')
        .execute();

      expect(invites).toHaveLength(1);
      expect(invites[0].status).toBe('PENDING');

      const memberUser = await deps.db
        .selectFrom('users')
        .select(['id', 'email', 'email_verified'])
        .where('email', '=', 'member@example.com')
        .executeTakeFirst();

      expect(memberUser).toBeDefined();
      expect(memberUser!.email_verified).toBe(true);

      const passwordIdentity = await deps.db
        .selectFrom('auth_identities')
        .select(['id', 'provider'])
        .where('user_id', '=', memberUser!.id)
        .where('provider', '=', 'password')
        .execute();

      expect(passwordIdentity).toHaveLength(1);

      const publicSignupTenantId = tenants.find((tenant) => tenant.key === 'goodwill-open')!.id;
      const memberships = await deps.db
        .selectFrom('memberships')
        .select(['id', 'role', 'status'])
        .where('tenant_id', '=', publicSignupTenantId)
        .where('user_id', '=', memberUser!.id)
        .execute();

      expect(memberships).toHaveLength(1);
      expect(memberships[0]).toMatchObject({ role: 'MEMBER', status: 'ACTIVE' });
    } finally {
      await close();
    }
  });
});
