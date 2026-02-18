import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';

import type { DbExecutor } from '../../src/shared/db/db';

import { buildTestApp } from '../helpers/build-test-app';
import { UserRepo } from '../../src/modules/users/dal/user.repo';
import { MembershipRepo } from '../../src/modules/memberships/dal/membership.repo';
import { selectMembershipByTenantAndUserSql } from '../../src/modules/memberships/dal/membership.query-sql';
import { getMembershipByTenantAndUser } from '../../src/modules/memberships/queries/membership.queries';
import {
  assertMembershipExists,
  assertMembershipIsActive,
  assertMembershipNotSuspended,
} from '../../src/modules/memberships/policies/membership-access.policy';
import type { Membership } from '../../src/modules/memberships/membership.types';

type SeedTenantRow = { id: string; key: string };

type SeedUserRow = { id: string; email: string };

async function seedTenantAndUser(db: DbExecutor): Promise<{
  tenant: SeedTenantRow;
  user: SeedUserRow;
  cleanup: () => Promise<void>;
}> {
  const tenant = await db
    .insertInto('tenants')
    .values({
      key: `t-${randomUUID().slice(0, 10)}`,
      name: 'Test Tenant',
      is_active: true,
      public_signup_enabled: false,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();

  const userRepo = new UserRepo(db);
  const user = await userRepo.insertUser({
    email: `test-${randomUUID().slice(0, 8)}@example.com`,
    name: 'Test User',
  });

  const cleanup = async (): Promise<void> => {
    await db.deleteFrom('memberships').where('tenant_id', '=', tenant.id).execute();
    await db.deleteFrom('users').where('id', '=', user.id).execute();
    await db.deleteFrom('tenants').where('id', '=', tenant.id).execute();
  };

  // Ensure we only return the fields the tests actually need (typed, minimal surface)
  return {
    tenant: { id: tenant.id, key: tenant.key },
    user: { id: user.id, email: user.email },
    cleanup,
  };
}

describe('memberships DAL', () => {
  it('insertMembership creates and select finds it', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const { tenant, user, cleanup } = await seedTenantAndUser(deps.db);
      try {
        const repo = new MembershipRepo(deps.db);
        const created = await repo.insertMembership({
          tenantId: tenant.id,
          userId: user.id,
          role: 'MEMBER',
          status: 'INVITED',
          invitedAt: new Date(),
        });
        expect(created.id).toBeDefined();

        const row = await selectMembershipByTenantAndUserSql(deps.db, {
          tenantId: tenant.id,
          userId: user.id,
        });
        expect(row).toBeDefined();
        expect(row!.role).toBe('MEMBER');
        expect(row!.status).toBe('INVITED');
      } finally {
        await cleanup();
      }
    } finally {
      await close();
    }
  });

  it('activateMembership transitions INVITED → ACTIVE', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const { tenant, user, cleanup } = await seedTenantAndUser(deps.db);
      try {
        const repo = new MembershipRepo(deps.db);
        const created = await repo.insertMembership({
          tenantId: tenant.id,
          userId: user.id,
          role: 'ADMIN',
          status: 'INVITED',
          invitedAt: new Date(),
        });

        const activated = await repo.activateMembership({
          membershipId: created.id,
          acceptedAt: new Date(),
        });
        expect(activated).toBe(true);

        const row = await selectMembershipByTenantAndUserSql(deps.db, {
          tenantId: tenant.id,
          userId: user.id,
        });
        expect(row!.status).toBe('ACTIVE');
        expect(row!.accepted_at).not.toBeNull();
      } finally {
        await cleanup();
      }
    } finally {
      await close();
    }
  });

  it('activateMembership idempotency: second call returns false', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const { tenant, user, cleanup } = await seedTenantAndUser(deps.db);
      try {
        const repo = new MembershipRepo(deps.db);
        const created = await repo.insertMembership({
          tenantId: tenant.id,
          userId: user.id,
          role: 'MEMBER',
          status: 'INVITED',
          invitedAt: new Date(),
        });

        expect(
          await repo.activateMembership({ membershipId: created.id, acceptedAt: new Date() }),
        ).toBe(true);
        expect(
          await repo.activateMembership({ membershipId: created.id, acceptedAt: new Date() }),
        ).toBe(false);
      } finally {
        await cleanup();
      }
    } finally {
      await close();
    }
  });

  it('getMembershipByTenantAndUser returns shaped domain type', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const { tenant, user, cleanup } = await seedTenantAndUser(deps.db);
      try {
        const repo = new MembershipRepo(deps.db);
        await repo.insertMembership({
          tenantId: tenant.id,
          userId: user.id,
          role: 'ADMIN',
          status: 'ACTIVE',
          invitedAt: new Date(),
        });

        const membership = await getMembershipByTenantAndUser(deps.db, {
          tenantId: tenant.id,
          userId: user.id,
        });
        expect(membership).toBeDefined();
        expect(membership!.role).toBe('ADMIN');
        expect(membership!.status).toBe('ACTIVE');
      } finally {
        await cleanup();
      }
    } finally {
      await close();
    }
  });

  it('wrong tenant returns undefined (tenant scoping)', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const { tenant, user, cleanup } = await seedTenantAndUser(deps.db);
      try {
        const repo = new MembershipRepo(deps.db);
        await repo.insertMembership({
          tenantId: tenant.id,
          userId: user.id,
          role: 'MEMBER',
          status: 'ACTIVE',
          invitedAt: new Date(),
        });

        const row = await selectMembershipByTenantAndUserSql(deps.db, {
          tenantId: '00000000-0000-0000-0000-000000000000',
          userId: user.id,
        });
        expect(row).toBeUndefined();
      } finally {
        await cleanup();
      }
    } finally {
      await close();
    }
  });
});

describe('membership policies', () => {
  const base: Membership = {
    id: 'mem-1',
    tenantId: 'ten-1',
    userId: 'usr-1',
    role: 'MEMBER',
    status: 'ACTIVE',
    invitedAt: new Date(),
    acceptedAt: new Date(),
    suspendedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  it('assertMembershipExists passes for existing', () => {
    expect(() => assertMembershipExists(base)).not.toThrow();
  });
  it('assertMembershipExists throws for undefined', () => {
    expect(() => assertMembershipExists(undefined)).toThrow();
  });
  it('assertMembershipIsActive passes for ACTIVE', () => {
    expect(() => assertMembershipIsActive(base)).not.toThrow();
  });
  it('assertMembershipIsActive throws for SUSPENDED', () => {
    expect(() => assertMembershipIsActive({ ...base, status: 'SUSPENDED' })).toThrow('suspended');
  });
  it('assertMembershipIsActive throws for INVITED', () => {
    expect(() => assertMembershipIsActive({ ...base, status: 'INVITED' })).toThrow('invitation');
  });
  it('assertMembershipNotSuspended passes for ACTIVE', () => {
    expect(() => assertMembershipNotSuspended(base)).not.toThrow();
  });
  it('assertMembershipNotSuspended passes for INVITED', () => {
    expect(() => assertMembershipNotSuspended({ ...base, status: 'INVITED' })).not.toThrow();
  });
  it('assertMembershipNotSuspended throws for SUSPENDED', () => {
    expect(() => assertMembershipNotSuspended({ ...base, status: 'SUSPENDED' })).toThrow(
      'suspended',
    );
  });
});
