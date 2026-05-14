import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import type { AppDeps } from '../../src/app/di';
import type { MembershipRole } from '../../src/modules/memberships/membership.types';
import type {
  PeopleTeamGroupResponse,
  PeopleTeamGroupsResponse,
} from '../../src/modules/people-teams/people-teams.types';
import { up as upPeopleTeamsMigration } from '../../src/shared/db/migrations/0022_people_teams_foundation';
import { getSessionCookieName } from '../../src/shared/session/session.types';
import { buildTestApp } from '../helpers/build-test-app';
import { hostForTenant } from '../helpers/tenant-host';

const sessionCookieName = getSessionCookieName(false);

type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
  };
};

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

async function createTenant(deps: AppDeps, namePrefix = 'People Teams Lifecycle Tenant') {
  const key = `ptw-${randomUUID().slice(0, 8)}`;

  return deps.db
    .insertInto('tenants')
    .values({
      key,
      name: `${namePrefix} ${key}`,
      is_active: true,
      public_signup_enabled: false,
      admin_invite_required: false,
      member_mfa_required: false,
      allowed_email_domains: [],
      allowed_sso: [],
      setup_completed_at: null,
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

async function createGroupFixture(opts: {
  deps: AppDeps;
  tenantId: string;
  name: string;
  normalizedName: string;
  level?: 'ADMIN' | 'AGENT' | 'USER';
  status?: 'ACTIVE' | 'ARCHIVED';
}) {
  return opts.deps.db
    .insertInto('tenant_groups')
    .values({
      tenant_id: opts.tenantId,
      name: opts.name,
      normalized_name: opts.normalizedName,
      description: null,
      level: opts.level ?? 'AGENT',
      status: opts.status ?? 'ACTIVE',
      archived_at: opts.status === 'ARCHIVED' ? new Date() : null,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();
}

async function countAuditEvents(opts: { deps: AppDeps; tenantId: string; action: string }) {
  const row = await opts.deps.db
    .selectFrom('audit_events')
    .select((eb) => eb.fn.count<string>('id').as('count'))
    .where('tenant_id', '=', opts.tenantId)
    .where('action', '=', opts.action)
    .executeTakeFirstOrThrow();

  return Number.parseInt(row.count, 10);
}

describe('people-teams group lifecycle writes', () => {
  it('allows ADMIN to create a tenant-scoped group and writes audit', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upPeopleTeamsMigration(deps.db);

      const tenant = await createTenant(deps);
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          name: '  Branch   Managers  ',
          description: 'Regional operations group',
          level: 'AGENT',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = readJson<PeopleTeamGroupResponse>(res);
      expect(body.group).toMatchObject({
        name: 'Branch   Managers',
        normalizedName: 'branch managers',
        description: 'Regional operations group',
        level: 'AGENT',
        status: 'ACTIVE',
        memberCount: 0,
      });

      const dbGroup = await deps.db
        .selectFrom('tenant_groups')
        .select(['tenant_id', 'created_by_membership_id', 'updated_by_membership_id'])
        .where('id', '=', body.group.id)
        .executeTakeFirstOrThrow();

      expect(dbGroup).toMatchObject({
        tenant_id: tenant.id,
        created_by_membership_id: admin.membershipId,
        updated_by_membership_id: admin.membershipId,
      });
      expect(
        await countAuditEvents({ deps, tenantId: tenant.id, action: 'people_teams.group_created' }),
      ).toBe(1);
    } finally {
      await close();
    }
  });

  it('rejects MEMBER and unauthenticated group creation', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upPeopleTeamsMigration(deps.db);

      const tenant = await createTenant(deps);
      const member = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'MEMBER',
      });

      const payload = { name: 'HR Agents', level: 'AGENT' };
      const unauthenticatedRes = await app.inject({
        method: 'POST',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key) },
        payload,
      });
      expect(unauthenticatedRes.statusCode).toBe(401);

      const memberRes = await app.inject({
        method: 'POST',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key), cookie: member.cookie },
        payload,
      });
      expect(memberRes.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('validates blank names, invalid levels, and duplicate normalized names per tenant', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upPeopleTeamsMigration(deps.db);

      const tenant = await createTenant(deps);
      const otherTenant = await createTenant(deps, 'Other Tenant');
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      const otherAdmin = await createSession({
        deps,
        tenantId: otherTenant.id,
        tenantKey: otherTenant.key,
        role: 'ADMIN',
      });

      const blankNameRes = await app.inject({
        method: 'POST',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { name: '   ', level: 'AGENT' },
      });
      expect(blankNameRes.statusCode).toBe(400);

      const invalidLevelRes = await app.inject({
        method: 'POST',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { name: 'HR Agents', level: 'MEMBER' },
      });
      expect(invalidLevelRes.statusCode).toBe(400);

      const createRes = await app.inject({
        method: 'POST',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { name: 'HR Agents', level: 'AGENT' },
      });
      expect(createRes.statusCode).toBe(201);

      const duplicateRes = await app.inject({
        method: 'POST',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { name: ' hr   agents ', level: 'AGENT' },
      });
      expect(duplicateRes.statusCode).toBe(409);
      expect(readJson<ErrorResponseBody>(duplicateRes).error.code).toBe('CONFLICT');

      const sameNameOtherTenantRes = await app.inject({
        method: 'POST',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(otherTenant.key), cookie: otherAdmin.cookie },
        payload: { name: 'HR Agents', level: 'AGENT' },
      });
      expect(sameNameOtherTenantRes.statusCode).toBe(201);
    } finally {
      await close();
    }
  });

  it('returns a clean conflict if duplicate group creation races the pre-check', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upPeopleTeamsMigration(deps.db);

      const tenant = await createTenant(deps);
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });

      const requests = await Promise.all([
        app.inject({
          method: 'POST',
          url: '/people-teams/groups',
          headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
          payload: { name: 'Concurrent HR Agents', level: 'AGENT' },
        }),
        app.inject({
          method: 'POST',
          url: '/people-teams/groups',
          headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
          payload: { name: ' concurrent   hr agents ', level: 'AGENT' },
        }),
      ]);

      expect(requests.map((res) => res.statusCode).sort()).toEqual([201, 409]);
      const conflict = requests.find((res) => res.statusCode === 409);
      if (!conflict) throw new Error('Expected one concurrent create request to return 409');
      expect(readJson<ErrorResponseBody>(conflict).error.message).toBe(
        'A People & Teams group with this name already exists.',
      );

      const groups = await deps.db
        .selectFrom('tenant_groups')
        .select(['id'])
        .where('tenant_id', '=', tenant.id)
        .where('normalized_name', '=', 'concurrent hr agents')
        .execute();

      expect(groups).toHaveLength(1);
    } finally {
      await close();
    }
  });

  it('allows ADMIN to update an active group and rejects duplicate or cross-tenant updates', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upPeopleTeamsMigration(deps.db);

      const tenant = await createTenant(deps);
      const otherTenant = await createTenant(deps, 'Other Tenant');
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      const member = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'MEMBER',
      });
      const group = await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'Old Name',
        normalizedName: 'old name',
      });
      await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'Existing Name',
        normalizedName: 'existing name',
      });
      const otherTenantGroup = await createGroupFixture({
        deps,
        tenantId: otherTenant.id,
        name: 'Other Tenant Group',
        normalizedName: 'other tenant group',
      });

      const updateRes = await app.inject({
        method: 'PUT',
        url: `/people-teams/groups/${group.id}`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { name: 'New Name', description: '', level: 'USER' },
      });
      expect(updateRes.statusCode).toBe(200);
      expect(readJson<PeopleTeamGroupResponse>(updateRes).group).toMatchObject({
        name: 'New Name',
        normalizedName: 'new name',
        description: null,
        level: 'USER',
      });

      const memberUpdateRes = await app.inject({
        method: 'PUT',
        url: `/people-teams/groups/${group.id}`,
        headers: { host: hostForTenant(tenant.key), cookie: member.cookie },
        payload: { name: 'Member Update', level: 'AGENT' },
      });
      expect(memberUpdateRes.statusCode).toBe(403);

      const duplicateRes = await app.inject({
        method: 'PUT',
        url: `/people-teams/groups/${group.id}`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { name: 'Existing Name', level: 'AGENT' },
      });
      expect(duplicateRes.statusCode).toBe(409);

      const crossTenantRes = await app.inject({
        method: 'PUT',
        url: `/people-teams/groups/${otherTenantGroup.id}`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { name: 'Cross Tenant Update', level: 'AGENT' },
      });
      expect(crossTenantRes.statusCode).toBe(404);

      expect(
        await countAuditEvents({ deps, tenantId: tenant.id, action: 'people_teams.group_updated' }),
      ).toBe(1);
    } finally {
      await close();
    }
  });

  it('archives active groups, excludes them from active lists, and rejects later mutation', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upPeopleTeamsMigration(deps.db);

      const tenant = await createTenant(deps);
      const otherTenant = await createTenant(deps, 'Other Tenant');
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      const member = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'MEMBER',
      });
      const group = await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'Archive Me',
        normalizedName: 'archive me',
      });
      const archivedGroup = await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'Already Archived',
        normalizedName: 'already archived',
        status: 'ARCHIVED',
      });
      const otherTenantGroup = await createGroupFixture({
        deps,
        tenantId: otherTenant.id,
        name: 'Other Archive',
        normalizedName: 'other archive',
      });

      const memberArchiveRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${group.id}/archive`,
        headers: { host: hostForTenant(tenant.key), cookie: member.cookie },
      });
      expect(memberArchiveRes.statusCode).toBe(403);

      const archiveRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${group.id}/archive`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(archiveRes.statusCode).toBe(200);
      expect(readJson<PeopleTeamGroupResponse>(archiveRes).group).toMatchObject({
        id: group.id,
        status: 'ARCHIVED',
      });

      const listRes = await app.inject({
        method: 'GET',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(listRes.statusCode).toBe(200);
      expect(readJson<PeopleTeamGroupsResponse>(listRes).groups).toHaveLength(0);

      const updateArchivedRes = await app.inject({
        method: 'PUT',
        url: `/people-teams/groups/${group.id}`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { name: 'Should Not Update', level: 'AGENT' },
      });
      expect(updateArchivedRes.statusCode).toBe(409);

      const archiveAlreadyArchivedRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${archivedGroup.id}/archive`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(archiveAlreadyArchivedRes.statusCode).toBe(409);

      const crossTenantArchiveRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${otherTenantGroup.id}/archive`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(crossTenantArchiveRes.statusCode).toBe(404);

      expect(
        await countAuditEvents({
          deps,
          tenantId: tenant.id,
          action: 'people_teams.group_archived',
        }),
      ).toBe(1);
    } finally {
      await close();
    }
  });
});
