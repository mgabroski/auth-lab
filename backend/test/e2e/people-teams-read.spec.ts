import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import type { AppDeps } from '../../src/app/di';
import { up as upPeopleTeamsMigration } from '../../src/shared/db/migrations/0022_people_teams_foundation';
import { getSessionCookieName } from '../../src/shared/session/session.types';
import type {
  PeopleTeamGroupsResponse,
  PeopleTeamPeopleResponse,
} from '../../src/modules/people-teams/people-teams.types';
import type {
  MembershipRole,
  MembershipStatus,
} from '../../src/modules/memberships/membership.types';
import { buildTestApp } from '../helpers/build-test-app';
import { hostForTenant } from '../helpers/tenant-host';

const sessionCookieName = getSessionCookieName(false);

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

async function createTenant(deps: AppDeps, namePrefix = 'People Teams Tenant') {
  const key = `pt-${randomUUID().slice(0, 8)}`;

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
  status?: MembershipStatus;
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
      status: opts.status ?? 'ACTIVE',
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
  status: MembershipStatus;
  email?: string;
  name?: string | null;
}): Promise<{ userId: string; membershipId: string }> {
  const user = await opts.deps.db
    .insertInto('users')
    .values({
      email: (opts.email ?? `person-${randomUUID().slice(0, 8)}@example.com`).toLowerCase(),
      name: opts.name ?? 'People Selector User',
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
      status: opts.status,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  return { userId: user.id, membershipId: membership.id };
}

describe('people-teams read foundation', () => {
  it('allows ADMIN to list active groups for the current tenant only', async () => {
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

      await deps.db
        .insertInto('tenant_groups')
        .values([
          {
            tenant_id: tenant.id,
            name: 'HR Agents',
            normalized_name: 'hr agents',
            description: 'Tenant-local active group',
            level: 'AGENT',
            status: 'ACTIVE',
          },
          {
            tenant_id: tenant.id,
            name: 'Archived Operators',
            normalized_name: 'archived operators',
            description: null,
            level: 'AGENT',
            status: 'ARCHIVED',
            archived_at: new Date(),
          },
          {
            tenant_id: otherTenant.id,
            name: 'Other Tenant Group',
            normalized_name: 'other tenant group',
            description: null,
            level: 'AGENT',
            status: 'ACTIVE',
          },
        ])
        .execute();

      const res = await app.inject({
        method: 'GET',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<PeopleTeamGroupsResponse>(res);
      expect(body.groups).toHaveLength(1);
      expect(body.groups[0]).toMatchObject({
        name: 'HR Agents',
        normalizedName: 'hr agents',
        description: 'Tenant-local active group',
        level: 'AGENT',
        status: 'ACTIVE',
      });
      expect(body.groups[0]?.memberCount).toBe(0);
    } finally {
      await close();
    }
  });

  it('rejects unauthenticated and MEMBER requests for group listing', async () => {
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

      const unauthenticatedRes = await app.inject({
        method: 'GET',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key) },
      });
      expect(unauthenticatedRes.statusCode).toBe(401);

      const memberRes = await app.inject({
        method: 'GET',
        url: '/people-teams/groups',
        headers: { host: hostForTenant(tenant.key), cookie: member.cookie },
      });
      expect(memberRes.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('returns only active current-tenant memberships in the people selector', async () => {
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
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
      });

      const activeMember = await createMembership({
        deps,
        tenantId: tenant.id,
        role: 'MEMBER',
        status: 'ACTIVE',
        email: `active-${randomUUID().slice(0, 8)}@example.com`,
        name: 'Active Member',
      });
      const invitedMember = await createMembership({
        deps,
        tenantId: tenant.id,
        role: 'MEMBER',
        status: 'INVITED',
        email: `invited-${randomUUID().slice(0, 8)}@example.com`,
      });
      const suspendedMember = await createMembership({
        deps,
        tenantId: tenant.id,
        role: 'MEMBER',
        status: 'SUSPENDED',
        email: `suspended-${randomUUID().slice(0, 8)}@example.com`,
      });
      const otherTenantMember = await createMembership({
        deps,
        tenantId: otherTenant.id,
        role: 'MEMBER',
        status: 'ACTIVE',
        email: `other-${randomUUID().slice(0, 8)}@example.com`,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/people-teams/people',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<PeopleTeamPeopleResponse>(res);
      const ids = body.people.map((person) => person.membershipId);

      expect(ids).toContain(admin.membershipId);
      expect(ids).toContain(activeMember.membershipId);
      expect(ids).not.toContain(invitedMember.membershipId);
      expect(ids).not.toContain(suspendedMember.membershipId);
      expect(ids).not.toContain(otherTenantMember.membershipId);

      const activePerson = body.people.find(
        (person) => person.membershipId === activeMember.membershipId,
      );
      expect(activePerson).toMatchObject({
        userId: activeMember.userId,
        name: 'Active Member',
        role: 'MEMBER',
        status: 'ACTIVE',
      });
    } finally {
      await close();
    }
  });

  it('fails closed when a valid session is replayed on a different tenant host', async () => {
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

      const res = await app.inject({
        method: 'GET',
        url: '/people-teams/people',
        headers: { host: hostForTenant(otherTenant.key), cookie: admin.cookie },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await close();
    }
  });
});
