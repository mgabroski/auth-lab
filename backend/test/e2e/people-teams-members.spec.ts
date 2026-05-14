import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import type { AppDeps } from '../../src/app/di';
import type {
  MembershipRole,
  MembershipStatus,
} from '../../src/modules/memberships/membership.types';
import type {
  PeopleTeamGroupMemberResponse,
  PeopleTeamGroupMembersResponse,
} from '../../src/modules/people-teams/people-teams.types';
import { up as upPeopleTeamsMigration } from '../../src/shared/db/migrations/0022_people_teams_foundation';
import { getSessionCookieName } from '../../src/shared/session/session.types';
import { buildTestApp } from '../helpers/build-test-app';
import { hostForTenant } from '../helpers/tenant-host';

const sessionCookieName = getSessionCookieName(false);

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

async function createTenant(deps: AppDeps, namePrefix = 'People Teams Members Tenant') {
  const key = `ptm-${randomUUID().slice(0, 8)}`;

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

async function createMembership(opts: {
  deps: AppDeps;
  tenantId: string;
  role?: MembershipRole;
  status?: MembershipStatus;
  email?: string;
  name?: string | null;
}): Promise<{ userId: string; membershipId: string; email: string }> {
  const email = (opts.email ?? `ptm-person-${randomUUID().slice(0, 8)}@example.com`).toLowerCase();
  const user = await opts.deps.db
    .insertInto('users')
    .values({
      email,
      name: opts.name ?? 'Group Member User',
      email_verified: true,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const membership = await opts.deps.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: opts.role ?? 'MEMBER',
      status: opts.status ?? 'ACTIVE',
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  return { userId: user.id, membershipId: membership.id, email };
}

async function createGroupFixture(opts: {
  deps: AppDeps;
  tenantId: string;
  name: string;
  normalizedName: string;
  status?: 'ACTIVE' | 'ARCHIVED';
}) {
  return opts.deps.db
    .insertInto('tenant_groups')
    .values({
      tenant_id: opts.tenantId,
      name: opts.name,
      normalized_name: opts.normalizedName,
      description: null,
      level: 'AGENT',
      status: opts.status ?? 'ACTIVE',
      archived_at: opts.status === 'ARCHIVED' ? new Date() : null,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();
}

async function addMemberFixture(opts: {
  deps: AppDeps;
  tenantId: string;
  groupId: string;
  membershipId: string;
  addedByMembershipId?: string;
}) {
  await opts.deps.db
    .insertInto('tenant_group_members')
    .values({
      tenant_id: opts.tenantId,
      group_id: opts.groupId,
      membership_id: opts.membershipId,
      added_by_membership_id: opts.addedByMembershipId ?? null,
    })
    .execute();
}

async function countGroupMemberRows(deps: AppDeps, membershipId: string) {
  const row = await deps.db
    .selectFrom('tenant_group_members')
    .select((eb) => eb.fn.count<string>('membership_id').as('count'))
    .where('membership_id', '=', membershipId)
    .executeTakeFirstOrThrow();

  return Number.parseInt(row.count, 10);
}

async function countMembershipRows(deps: AppDeps, membershipId: string) {
  const row = await deps.db
    .selectFrom('memberships')
    .select((eb) => eb.fn.count<string>('id').as('count'))
    .where('id', '=', membershipId)
    .executeTakeFirstOrThrow();

  return Number.parseInt(row.count, 10);
}

async function countUserRows(deps: AppDeps, userId: string) {
  const row = await deps.db
    .selectFrom('users')
    .select((eb) => eb.fn.count<string>('id').as('count'))
    .where('id', '=', userId)
    .executeTakeFirstOrThrow();

  return Number.parseInt(row.count, 10);
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

describe('people-teams group membership writes', () => {
  it('allows ADMIN to list only members of a current-tenant group', async () => {
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
      const memberSession = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'MEMBER',
      });
      const group = await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'HR Agents',
        normalizedName: 'hr agents',
      });
      const otherGroup = await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'IT Agents',
        normalizedName: 'it agents',
      });
      const otherTenantGroup = await createGroupFixture({
        deps,
        tenantId: otherTenant.id,
        name: 'Other Tenant Group',
        normalizedName: 'other tenant group',
      });
      const firstMember = await createMembership({
        deps,
        tenantId: tenant.id,
        name: 'First Member',
      });
      const secondMember = await createMembership({
        deps,
        tenantId: tenant.id,
        name: 'Second Member',
      });
      await addMemberFixture({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        membershipId: firstMember.membershipId,
      });
      await addMemberFixture({
        deps,
        tenantId: tenant.id,
        groupId: otherGroup.id,
        membershipId: secondMember.membershipId,
      });

      const unauthenticatedRes = await app.inject({
        method: 'GET',
        url: `/people-teams/groups/${group.id}/members`,
        headers: { host: hostForTenant(tenant.key) },
      });
      expect(unauthenticatedRes.statusCode).toBe(401);

      const memberRes = await app.inject({
        method: 'GET',
        url: `/people-teams/groups/${group.id}/members`,
        headers: { host: hostForTenant(tenant.key), cookie: memberSession.cookie },
      });
      expect(memberRes.statusCode).toBe(403);

      const res = await app.inject({
        method: 'GET',
        url: `/people-teams/groups/${group.id}/members`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(res.statusCode).toBe(200);
      const body = readJson<PeopleTeamGroupMembersResponse>(res);
      expect(body.members.map((member) => member.membershipId)).toEqual([firstMember.membershipId]);
      expect(body.members[0]).toMatchObject({
        userId: firstMember.userId,
        email: firstMember.email,
        name: 'First Member',
        role: 'MEMBER',
        status: 'ACTIVE',
      });

      const crossTenantRes = await app.inject({
        method: 'GET',
        url: `/people-teams/groups/${otherTenantGroup.id}/members`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(crossTenantRes.statusCode).toBe(404);
    } finally {
      await close();
    }
  });

  it('allows ADMIN to add an active tenant membership and writes audit', async () => {
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
      const group = await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'Local Operators',
        normalizedName: 'local operators',
      });
      const member = await createMembership({ deps, tenantId: tenant.id, name: 'Operator One' });

      const res = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${group.id}/members`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { membershipId: member.membershipId },
      });
      expect(res.statusCode).toBe(201);
      expect(readJson<PeopleTeamGroupMemberResponse>(res).member).toMatchObject({
        membershipId: member.membershipId,
        userId: member.userId,
        email: member.email,
        name: 'Operator One',
        role: 'MEMBER',
        status: 'ACTIVE',
      });

      expect(await countGroupMemberRows(deps, member.membershipId)).toBe(1);
      expect(
        await countAuditEvents({ deps, tenantId: tenant.id, action: 'people_teams.member_added' }),
      ).toBe(1);
    } finally {
      await close();
    }
  });

  it('rejects invalid member adds without creating duplicate rows', async () => {
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
      const memberSession = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'MEMBER',
      });
      const group = await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'Benefits Team',
        normalizedName: 'benefits team',
      });
      const archivedGroup = await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'Archived Team',
        normalizedName: 'archived team',
        status: 'ARCHIVED',
      });
      const activeMember = await createMembership({ deps, tenantId: tenant.id });
      const invitedMember = await createMembership({
        deps,
        tenantId: tenant.id,
        status: 'INVITED',
      });
      const suspendedMember = await createMembership({
        deps,
        tenantId: tenant.id,
        status: 'SUSPENDED',
      });
      const otherTenantMember = await createMembership({ deps, tenantId: otherTenant.id });
      await addMemberFixture({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        membershipId: activeMember.membershipId,
      });

      const unauthenticatedRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${group.id}/members`,
        headers: { host: hostForTenant(tenant.key) },
        payload: { membershipId: activeMember.membershipId },
      });
      expect(unauthenticatedRes.statusCode).toBe(401);

      const memberRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${group.id}/members`,
        headers: { host: hostForTenant(tenant.key), cookie: memberSession.cookie },
        payload: { membershipId: invitedMember.membershipId },
      });
      expect(memberRes.statusCode).toBe(403);

      const crossTenantRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${group.id}/members`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { membershipId: otherTenantMember.membershipId },
      });
      expect(crossTenantRes.statusCode).toBe(404);

      const invitedRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${group.id}/members`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { membershipId: invitedMember.membershipId },
      });
      expect(invitedRes.statusCode).toBe(409);

      const suspendedRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${group.id}/members`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { membershipId: suspendedMember.membershipId },
      });
      expect(suspendedRes.statusCode).toBe(409);

      const archivedGroupRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${archivedGroup.id}/members`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { membershipId: invitedMember.membershipId },
      });
      expect(archivedGroupRes.statusCode).toBe(409);

      const duplicateRes = await app.inject({
        method: 'POST',
        url: `/people-teams/groups/${group.id}/members`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: { membershipId: activeMember.membershipId },
      });
      expect(duplicateRes.statusCode).toBe(409);
      expect(await countGroupMemberRows(deps, activeMember.membershipId)).toBe(1);
    } finally {
      await close();
    }
  });

  it('allows ADMIN to remove a member without deleting the user or tenant membership', async () => {
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
      const memberSession = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'MEMBER',
      });
      const group = await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'Remove Team',
        normalizedName: 'remove team',
      });
      const archivedGroup = await createGroupFixture({
        deps,
        tenantId: tenant.id,
        name: 'Archived Remove Team',
        normalizedName: 'archived remove team',
        status: 'ARCHIVED',
      });
      const otherTenantGroup = await createGroupFixture({
        deps,
        tenantId: otherTenant.id,
        name: 'Other Remove Team',
        normalizedName: 'other remove team',
      });
      const target = await createMembership({ deps, tenantId: tenant.id, name: 'Remove Target' });
      await addMemberFixture({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        membershipId: target.membershipId,
      });
      await addMemberFixture({
        deps,
        tenantId: tenant.id,
        groupId: archivedGroup.id,
        membershipId: target.membershipId,
      });

      const unauthenticatedRes = await app.inject({
        method: 'DELETE',
        url: `/people-teams/groups/${group.id}/members/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key) },
      });
      expect(unauthenticatedRes.statusCode).toBe(401);

      const memberRes = await app.inject({
        method: 'DELETE',
        url: `/people-teams/groups/${group.id}/members/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: memberSession.cookie },
      });
      expect(memberRes.statusCode).toBe(403);

      const archivedGroupRes = await app.inject({
        method: 'DELETE',
        url: `/people-teams/groups/${archivedGroup.id}/members/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(archivedGroupRes.statusCode).toBe(409);

      const crossTenantRes = await app.inject({
        method: 'DELETE',
        url: `/people-teams/groups/${otherTenantGroup.id}/members/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(crossTenantRes.statusCode).toBe(404);

      const res = await app.inject({
        method: 'DELETE',
        url: `/people-teams/groups/${group.id}/members/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(res.statusCode).toBe(200);
      expect(readJson<PeopleTeamGroupMemberResponse>(res).member).toMatchObject({
        membershipId: target.membershipId,
        userId: target.userId,
        email: target.email,
        name: 'Remove Target',
      });

      expect(await countGroupMemberRows(deps, target.membershipId)).toBe(1);
      expect(await countMembershipRows(deps, target.membershipId)).toBe(1);
      expect(await countUserRows(deps, target.userId)).toBe(1);
      expect(
        await countAuditEvents({
          deps,
          tenantId: tenant.id,
          action: 'people_teams.member_removed',
        }),
      ).toBe(1);

      const removeAgainRes = await app.inject({
        method: 'DELETE',
        url: `/people-teams/groups/${group.id}/members/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(removeAgainRes.statusCode).toBe(404);
    } finally {
      await close();
    }
  });
});
