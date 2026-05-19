import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import type { AppDeps } from '../../src/app/di';
import type { MembershipRole } from '../../src/modules/memberships/membership.types';
import type {
  OperationalAccessCatalogResponse,
  OperationalAccessGroupConfigurationResponse,
  OperationalAccessGroupsResponse,
} from '../../src/modules/operational-access/operational-access.types';
import { up as upPeopleTeamsMigration } from '../../src/shared/db/migrations/0022_people_teams_foundation';
import { up as upOperationalAccessCapabilityMigration } from '../../src/shared/db/migrations/0025_operational_access_capability';
import { up as upOperationalAccessGroupGrantsMigration } from '../../src/shared/db/migrations/0026_operational_access_group_grants';
import { getSessionCookieName } from '../../src/shared/session/session.types';
import { buildTestApp } from '../helpers/build-test-app';
import { hostForTenant } from '../helpers/tenant-host';

const sessionCookieName = getSessionCookieName(false);

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

async function migrateForOperationalAccess(deps: AppDeps): Promise<void> {
  await upPeopleTeamsMigration(deps.db);
  await upOperationalAccessCapabilityMigration(deps.db);
  await upOperationalAccessGroupGrantsMigration(deps.db);
}

async function createTenant(deps: AppDeps, operationalAccessEnabled = true) {
  const key = `oa-${randomUUID().slice(0, 8)}`;

  return deps.db
    .insertInto('tenants')
    .values({
      key,
      name: `Operational Access Tenant ${key}`,
      is_active: true,
      public_signup_enabled: false,
      admin_invite_required: false,
      member_mfa_required: false,
      allowed_email_domains: [],
      allowed_sso: [],
      setup_completed_at: null,
      operational_access_enabled: operationalAccessEnabled,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

async function createSession(opts: {
  deps: AppDeps;
  tenantId: string;
  tenantKey: string;
  role: MembershipRole;
  email?: string;
}): Promise<{ cookie: string; userId: string; membershipId: string }> {
  const user = await opts.deps.db
    .insertInto('users')
    .values({
      email: (
        opts.email ?? `${opts.role.toLowerCase()}-${randomUUID().slice(0, 8)}@example.com`
      ).toLowerCase(),
      name: `${opts.role} User`,
      email_verified: true,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const membership = await opts.deps.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: opts.role,
      status: 'ACTIVE',
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const sessionId = await opts.deps.sessionStore.create({
    tenantId: opts.tenantId,
    tenantKey: opts.tenantKey,
    userId: user.id,
    membershipId: membership.id,
    role: opts.role,
    mfaVerified: true,
    emailVerified: true,
    createdAt: new Date().toISOString(),
  });

  return {
    cookie: `${sessionCookieName}=${sessionId}`,
    userId: user.id,
    membershipId: membership.id,
  };
}

async function createMembership(opts: {
  deps: AppDeps;
  tenantId: string;
  role: MembershipRole;
  email?: string;
}): Promise<{ userId: string; membershipId: string }> {
  const user = await opts.deps.db
    .insertInto('users')
    .values({
      email: (opts.email ?? `oa-person-${randomUUID().slice(0, 8)}@example.com`).toLowerCase(),
      name: `${opts.role} Person`,
      email_verified: true,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const membership = await opts.deps.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: opts.role,
      status: 'ACTIVE',
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  return { userId: user.id, membershipId: membership.id };
}

async function createGroup(opts: {
  deps: AppDeps;
  tenantId: string;
  name: string;
  level?: 'ADMIN' | 'AGENT' | 'USER';
  status?: 'ACTIVE' | 'ARCHIVED';
}) {
  const normalizedName = `${opts.name}-${randomUUID().slice(0, 8)}`.toLowerCase();

  return opts.deps.db
    .insertInto('tenant_groups')
    .values({
      tenant_id: opts.tenantId,
      name: opts.name,
      normalized_name: normalizedName,
      description: null,
      level: opts.level ?? 'AGENT',
      status: opts.status ?? 'ACTIVE',
      archived_at: opts.status === 'ARCHIVED' ? new Date() : null,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();
}

async function addGroupMember(opts: {
  deps: AppDeps;
  tenantId: string;
  groupId: string;
  membershipId: string;
}) {
  await opts.deps.db
    .insertInto('tenant_group_members')
    .values({
      tenant_id: opts.tenantId,
      group_id: opts.groupId,
      membership_id: opts.membershipId,
    })
    .execute();
}

describe('operational access group grant foundation', () => {
  it('lists the product-defined catalog and active Agent groups only when capability is enabled', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps, true);
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      await createGroup({ deps, tenantId: tenant.id, name: 'Managers', level: 'AGENT' });
      await createGroup({ deps, tenantId: tenant.id, name: 'Admins', level: 'ADMIN' });

      const catalogRes = await app.inject({
        method: 'GET',
        url: '/operational-access/catalog',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(catalogRes.statusCode).toBe(200);
      const catalog = readJson<OperationalAccessCatalogResponse>(catalogRes);
      expect(catalog.catalog.primaryWhere.map((item) => item.key)).toEqual([
        'TENANT_WIDE',
        'ASSIGNED_AREAS',
        'RESPONSIBLE_FOR',
        'REVIEW_QUEUE',
      ]);
      expect(catalog.catalog.primaryWhere.map((item) => item.key)).not.toContain('OVERSIGHT');
      expect(catalog.catalog.coverage.assignedAreas.available).toBe(false);
      expect(catalog.catalog.coverage.responsibleFor.available).toBe(true);

      const groupsRes = await app.inject({
        method: 'GET',
        url: '/operational-access/groups',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(groupsRes.statusCode).toBe(200);
      const groups = readJson<OperationalAccessGroupsResponse>(groupsRes);
      expect(groups.groups).toHaveLength(1);
      expect(groups.groups[0]).toMatchObject({ name: 'Managers', level: 'AGENT' });
    } finally {
      await close();
    }
  });

  it('saves valid group grants and rejects invalid or duplicate grant requests', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps, true);
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      const group = await createGroup({
        deps,
        tenantId: tenant.id,
        name: 'Task Operators',
        level: 'AGENT',
      });

      const validRes = await app.inject({
        method: 'PUT',
        url: `/operational-access/groups/${group.id}/grants`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          grants: [
            {
              actionKey: 'tasks.manage',
              primaryWhere: 'RESPONSIBLE_FOR',
              whichRecordsKey: 'open_tasks',
            },
          ],
        },
      });
      expect(validRes.statusCode).toBe(200);
      const validBody = readJson<OperationalAccessGroupConfigurationResponse>(validRes);
      expect(validBody.groupConfiguration.grants).toHaveLength(1);
      expect(validBody.groupConfiguration.safety.runtimeVisibilityChanged).toBe(false);
      expect(validBody.groupConfiguration.safety.effectiveAccessResolverShipped).toBe(false);

      const duplicateRes = await app.inject({
        method: 'PUT',
        url: `/operational-access/groups/${group.id}/grants`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          grants: [
            { actionKey: 'tasks.view', primaryWhere: 'TENANT_WIDE', whichRecordsKey: 'all_tasks' },
            { actionKey: 'tasks.view', primaryWhere: 'TENANT_WIDE', whichRecordsKey: 'open_tasks' },
          ],
        },
      });
      expect(duplicateRes.statusCode).toBe(409);

      const invalidWhereRes = await app.inject({
        method: 'PUT',
        url: `/operational-access/groups/${group.id}/grants`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          grants: [
            {
              actionKey: 'tasks.view',
              primaryWhere: 'OVERSIGHT',
              whichRecordsKey: 'all_tasks',
            },
          ],
        },
      });
      expect(invalidWhereRes.statusCode).toBe(400);

      const invalidCombinationRes = await app.inject({
        method: 'PUT',
        url: `/operational-access/groups/${group.id}/grants`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          grants: [
            {
              actionKey: 'documents.review',
              primaryWhere: 'TENANT_WIDE',
              whichRecordsKey: 'documents_requiring_review',
            },
          ],
        },
      });
      expect(invalidCombinationRes.statusCode).toBe(400);
    } finally {
      await close();
    }
  });

  it('rejects archived, non-Agent, cross-tenant, and disabled-capability writes', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps, true);
      const disabledTenant = await createTenant(deps, false);
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      const disabledAdmin = await createSession({
        deps,
        tenantId: disabledTenant.id,
        tenantKey: disabledTenant.key,
        role: 'ADMIN',
      });
      const archivedGroup = await createGroup({
        deps,
        tenantId: tenant.id,
        name: 'Archived Agents',
        level: 'AGENT',
        status: 'ARCHIVED',
      });
      const userGroup = await createGroup({
        deps,
        tenantId: tenant.id,
        name: 'Users',
        level: 'USER',
      });
      const otherTenantGroup = await createGroup({
        deps,
        tenantId: disabledTenant.id,
        name: 'Other Agents',
        level: 'AGENT',
      });

      for (const groupId of [archivedGroup.id, userGroup.id]) {
        const res = await app.inject({
          method: 'PUT',
          url: `/operational-access/groups/${groupId}/grants`,
          headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
          payload: {
            grants: [
              {
                actionKey: 'tasks.view',
                primaryWhere: 'TENANT_WIDE',
                whichRecordsKey: 'all_tasks',
              },
            ],
          },
        });
        expect(res.statusCode).toBe(409);
      }

      const crossTenantRes = await app.inject({
        method: 'PUT',
        url: `/operational-access/groups/${otherTenantGroup.id}/grants`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          grants: [
            { actionKey: 'tasks.view', primaryWhere: 'TENANT_WIDE', whichRecordsKey: 'all_tasks' },
          ],
        },
      });
      expect(crossTenantRes.statusCode).toBe(404);

      const disabledCapabilityRes = await app.inject({
        method: 'GET',
        url: '/operational-access/groups',
        headers: { host: hostForTenant(disabledTenant.key), cookie: disabledAdmin.cookie },
      });
      expect(disabledCapabilityRes.statusCode).toBe(404);
    } finally {
      await close();
    }
  });

  it('saves Responsible For coverage only for active Agent group members and active tenant targets', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps, true);
      const otherTenant = await createTenant(deps, true);
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      const group = await createGroup({
        deps,
        tenantId: tenant.id,
        name: 'Managers',
        level: 'AGENT',
      });
      const agent = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const target = await createMembership({ deps, tenantId: tenant.id, role: 'USER' });
      const otherTarget = await createMembership({ deps, tenantId: otherTenant.id, role: 'USER' });

      const agentNotInGroupRes = await app.inject({
        method: 'PUT',
        url: `/operational-access/groups/${group.id}/responsible-for`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          assignments: [
            { agentMembershipId: agent.membershipId, targetMembershipId: target.membershipId },
          ],
        },
      });
      expect(agentNotInGroupRes.statusCode).toBe(400);

      await addGroupMember({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        membershipId: agent.membershipId,
      });

      const validRes = await app.inject({
        method: 'PUT',
        url: `/operational-access/groups/${group.id}/responsible-for`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          assignments: [
            { agentMembershipId: agent.membershipId, targetMembershipId: target.membershipId },
          ],
        },
      });
      expect(validRes.statusCode).toBe(200);
      const body = readJson<OperationalAccessGroupConfigurationResponse>(validRes);
      expect(body.groupConfiguration.responsibleFor).toHaveLength(1);
      expect(body.groupConfiguration.responsibleFor[0].targetMembershipId).toBe(
        target.membershipId,
      );

      const crossTenantTargetRes = await app.inject({
        method: 'PUT',
        url: `/operational-access/groups/${group.id}/responsible-for`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          assignments: [
            { agentMembershipId: agent.membershipId, targetMembershipId: otherTarget.membershipId },
          ],
        },
      });
      expect(crossTenantTargetRes.statusCode).toBe(404);
    } finally {
      await close();
    }
  });

  it('does not let Agent group membership access admin or Operational Access routes', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps, true);
      const group = await createGroup({
        deps,
        tenantId: tenant.id,
        name: 'Operators',
        level: 'AGENT',
      });
      const agentSession = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'AGENT',
      });
      await addGroupMember({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        membershipId: agentSession.membershipId,
      });
      await deps.db
        .insertInto('tenant_oa_group_grants')
        .values({
          tenant_id: tenant.id,
          group_id: group.id,
          action_key: 'tasks.view',
          primary_where: 'TENANT_WIDE',
          which_records_key: 'all_tasks',
        })
        .execute();

      for (const url of [
        '/settings/overview',
        '/people-teams/groups',
        '/operational-access/groups',
      ]) {
        const res = await app.inject({
          method: 'GET',
          url,
          headers: { host: hostForTenant(tenant.key), cookie: agentSession.cookie },
        });
        expect(res.statusCode, url).toBe(403);
      }
    } finally {
      await close();
    }
  });
});
