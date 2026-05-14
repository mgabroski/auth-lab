import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { sql } from 'kysely';

import {
  down as downRuntimeRoleMigration,
  up as upRuntimeRoleMigration,
} from '../../src/shared/db/migrations/0023_runtime_membership_roles';
import type { DbExecutor } from '../../src/shared/db/db';
import { buildTestApp } from '../helpers/build-test-app';

type TenantRow = { id: string; key: string };
type UserRow = { id: string };

type RoleRow = { role: string };

async function createTenant(db: DbExecutor): Promise<TenantRow> {
  return db
    .insertInto('tenants')
    .values({
      key: `tenant-${randomUUID()}`,
      name: 'Runtime Role Tenant',
      is_active: true,
      public_signup_enabled: true,
      admin_invite_required: false,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

async function createUser(db: DbExecutor): Promise<UserRow> {
  return db
    .insertInto('users')
    .values({
      email: `user-${randomUUID()}@example.com`,
      name: 'Runtime Role User',
      email_verified: true,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();
}

async function insertMembership(db: DbExecutor, params: { tenantId: string; role: string }) {
  const user = await createUser(db);

  return db
    .insertInto('memberships')
    .values({
      tenant_id: params.tenantId,
      user_id: user.id,
      role: params.role,
      status: 'ACTIVE',
      accepted_at: new Date(),
    })
    .returning(['id', 'role'])
    .executeTakeFirstOrThrow();
}

async function insertInvite(db: DbExecutor, params: { tenantId: string; role: string }) {
  return db
    .insertInto('invites')
    .values({
      tenant_id: params.tenantId,
      email: `invite-${randomUUID()}@example.com`,
      role: params.role,
      status: 'PENDING',
      token_hash: `hash-${randomUUID()}`,
      expires_at: new Date(Date.now() + 60_000),
      created_by_user_id: null,
    })
    .returning(['id', 'role'])
    .executeTakeFirstOrThrow();
}

describe('runtime membership role foundation', () => {
  it('migration backfills legacy MEMBER memberships and invites to USER while preserving ADMIN', async () => {
    const { deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await downRuntimeRoleMigration(deps.db);

      const tenant = await createTenant(deps.db);
      await insertMembership(deps.db, { tenantId: tenant.id, role: 'MEMBER' });
      await insertMembership(deps.db, { tenantId: tenant.id, role: 'ADMIN' });
      await insertInvite(deps.db, { tenantId: tenant.id, role: 'MEMBER' });
      await insertInvite(deps.db, { tenantId: tenant.id, role: 'ADMIN' });

      await upRuntimeRoleMigration(deps.db);

      const membershipRoles = await deps.db
        .selectFrom('memberships')
        .select(['role'])
        .where('tenant_id', '=', tenant.id)
        .orderBy('role')
        .execute();
      const inviteRoles = await deps.db
        .selectFrom('invites')
        .select(['role'])
        .where('tenant_id', '=', tenant.id)
        .orderBy('role')
        .execute();

      expect(membershipRoles.map((row: RoleRow) => row.role)).toEqual(['ADMIN', 'USER']);
      expect(inviteRoles.map((row: RoleRow) => row.role)).toEqual(['ADMIN', 'USER']);
    } finally {
      await upRuntimeRoleMigration(deps.db);
      await close();
    }
  });

  it('allows ADMIN / AGENT / USER and rejects invalid membership and invite roles', async () => {
    const { deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upRuntimeRoleMigration(deps.db);

      const tenant = await createTenant(deps.db);

      await expect(
        insertMembership(deps.db, { tenantId: tenant.id, role: 'ADMIN' }),
      ).resolves.toBeTruthy();
      await expect(
        insertMembership(deps.db, { tenantId: tenant.id, role: 'AGENT' }),
      ).resolves.toBeTruthy();
      await expect(
        insertMembership(deps.db, { tenantId: tenant.id, role: 'USER' }),
      ).resolves.toBeTruthy();
      await expect(
        insertMembership(deps.db, { tenantId: tenant.id, role: 'OWNER' }),
      ).rejects.toThrow();

      await expect(
        insertInvite(deps.db, { tenantId: tenant.id, role: 'ADMIN' }),
      ).resolves.toBeTruthy();
      await expect(
        insertInvite(deps.db, { tenantId: tenant.id, role: 'AGENT' }),
      ).resolves.toBeTruthy();
      await expect(
        insertInvite(deps.db, { tenantId: tenant.id, role: 'USER' }),
      ).resolves.toBeTruthy();
      await expect(insertInvite(deps.db, { tenantId: tenant.id, role: 'OWNER' })).rejects.toThrow();
    } finally {
      await close();
    }
  });
});
