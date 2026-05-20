import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';

import type { AppDeps } from '../../src/app/di';
import type { MembershipRole } from '../../src/modules/memberships/membership.types';
import type {
  OperationalAccessAdvancedCoverageResponse,
  OperationalAccessRuntimePeopleResponse,
  OperationalAccessRuntimePersonResponse,
} from '../../src/modules/operational-access/operational-access.types';
import { up as upPeopleTeamsMigration } from '../../src/shared/db/migrations/0022_people_teams_foundation';
import { up as upOperationalAccessCapabilityMigration } from '../../src/shared/db/migrations/0025_operational_access_capability';
import { up as upOperationalAccessGroupGrantsMigration } from '../../src/shared/db/migrations/0026_operational_access_group_grants';
import { up as upOperationalAccessResolverMigration } from '../../src/shared/db/migrations/0027_operational_access_resolver_and_exceptions';
import { up as upOperationalAccessAdvancedCoverageVersionsMigration } from '../../src/shared/db/migrations/0028_operational_access_advanced_coverage_versions';
import { getSessionCookieName } from '../../src/shared/session/session.types';
import { buildTestApp } from '../helpers/build-test-app';
import { hostForTenant } from '../helpers/tenant-host';

const sessionCookieName = getSessionCookieName(false);

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

async function advancedCoverageVersion(
  app: FastifyInstance,
  tenantKey: string,
  cookie: string,
): Promise<number> {
  const res = await app.inject({
    method: 'GET',
    url: '/operational-access/advanced-coverage',
    headers: { host: hostForTenant(tenantKey), cookie },
  });
  expect(res.statusCode).toBe(200);
  return readJson<OperationalAccessAdvancedCoverageResponse>(res).version;
}

async function migrateForOperationalAccess(deps: AppDeps): Promise<void> {
  await upPeopleTeamsMigration(deps.db);
  await upOperationalAccessCapabilityMigration(deps.db);
  await upOperationalAccessGroupGrantsMigration(deps.db);
  await upOperationalAccessResolverMigration(deps.db);
  await upOperationalAccessAdvancedCoverageVersionsMigration(deps.db);
}

async function createTenant(deps: AppDeps) {
  const key = `oa4-${randomUUID().slice(0, 8)}`;

  return deps.db
    .insertInto('tenants')
    .values({
      key,
      name: `Operational Access Resolver Tenant ${key}`,
      is_active: true,
      public_signup_enabled: false,
      admin_invite_required: false,
      member_mfa_required: false,
      allowed_email_domains: [],
      allowed_sso: [],
      setup_completed_at: null,
      operational_access_enabled: true,
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
      name: `${opts.role} Resolver User`,
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
  name?: string;
}): Promise<{ userId: string; membershipId: string }> {
  const user = await opts.deps.db
    .insertInto('users')
    .values({
      email: (opts.email ?? `oa4-person-${randomUUID().slice(0, 8)}@example.com`).toLowerCase(),
      name: opts.name ?? `${opts.role} Resolver Person`,
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

async function createCookieForMembership(opts: {
  deps: AppDeps;
  tenantId: string;
  tenantKey: string;
  role: MembershipRole;
  userId: string;
  membershipId: string;
}): Promise<string> {
  const sessionId = await opts.deps.sessionStore.create({
    tenantId: opts.tenantId,
    tenantKey: opts.tenantKey,
    userId: opts.userId,
    membershipId: opts.membershipId,
    role: opts.role,
    mfaVerified: true,
    emailVerified: true,
    createdAt: new Date().toISOString(),
  });

  return `${sessionCookieName}=${sessionId}`;
}

async function createAgentGroup(deps: AppDeps, tenantId: string) {
  return deps.db
    .insertInto('tenant_groups')
    .values({
      tenant_id: tenantId,
      name: `Managers ${randomUUID().slice(0, 6)}`,
      normalized_name: `managers-${randomUUID().slice(0, 8)}`,
      description: null,
      level: 'AGENT',
      status: 'ACTIVE',
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

async function addPersonalCardGrant(opts: { deps: AppDeps; tenantId: string; groupId: string }) {
  await opts.deps.db
    .insertInto('tenant_oa_group_grants')
    .values({
      tenant_id: opts.tenantId,
      group_id: opts.groupId,
      action_key: 'personal_cards.view',
      primary_where: 'RESPONSIBLE_FOR',
      which_records_key: 'personal_cards_requiring_attention',
    })
    .execute();
}

async function addResponsibleFor(opts: {
  deps: AppDeps;
  tenantId: string;
  groupId: string;
  agentMembershipId: string;
  targetMembershipId: string;
}) {
  await opts.deps.db
    .insertInto('tenant_oa_responsible_for')
    .values({
      tenant_id: opts.tenantId,
      group_id: opts.groupId,
      agent_membership_id: opts.agentMembershipId,
      target_membership_id: opts.targetMembershipId,
    })
    .execute();
}

function membershipIds(body: OperationalAccessRuntimePeopleResponse): string[] {
  return body.people.map((person) => person.membershipId).sort();
}

describe('operational access resolver proof surface', () => {
  it('allows Admin by Admin level and limits User to own self-service data', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps);
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      const user = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'USER',
      });
      const other = await createMembership({ deps, tenantId: tenant.id, role: 'USER' });

      const adminRes = await app.inject({
        method: 'GET',
        url: '/operational-access/runtime/people',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(adminRes.statusCode).toBe(200);
      expect(membershipIds(readJson<OperationalAccessRuntimePeopleResponse>(adminRes))).toEqual(
        expect.arrayContaining([admin.membershipId, user.membershipId, other.membershipId]),
      );

      const userRes = await app.inject({
        method: 'GET',
        url: '/operational-access/runtime/people',
        headers: { host: hostForTenant(tenant.key), cookie: user.cookie },
      });
      expect(userRes.statusCode).toBe(200);
      expect(membershipIds(readJson<OperationalAccessRuntimePeopleResponse>(userRes))).toEqual([
        user.membershipId,
      ]);

      const deniedRes = await app.inject({
        method: 'GET',
        url: `/operational-access/runtime/people/${other.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: user.cookie },
      });
      expect(deniedRes.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('requires grant plus matching Responsible For coverage and masks sensitive fields for Agents', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps);
      const group = await createAgentGroup(deps, tenant.id);
      const agent = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'AGENT',
      });
      const target = await createMembership({
        deps,
        tenantId: tenant.id,
        role: 'USER',
        email: 'target@example.com',
      });
      const other = await createMembership({ deps, tenantId: tenant.id, role: 'USER' });

      await addGroupMember({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        membershipId: agent.membershipId,
      });

      const noGrantRes = await app.inject({
        method: 'GET',
        url: '/operational-access/runtime/people',
        headers: { host: hostForTenant(tenant.key), cookie: agent.cookie },
      });
      expect(noGrantRes.statusCode).toBe(200);
      expect(readJson<OperationalAccessRuntimePeopleResponse>(noGrantRes).people).toHaveLength(0);

      await addPersonalCardGrant({ deps, tenantId: tenant.id, groupId: group.id });
      const noCoverageRes = await app.inject({
        method: 'GET',
        url: '/operational-access/runtime/people',
        headers: { host: hostForTenant(tenant.key), cookie: agent.cookie },
      });
      expect(noCoverageRes.statusCode).toBe(200);
      expect(readJson<OperationalAccessRuntimePeopleResponse>(noCoverageRes).people).toHaveLength(
        0,
      );

      await addResponsibleFor({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        agentMembershipId: agent.membershipId,
        targetMembershipId: target.membershipId,
      });

      const allowedRes = await app.inject({
        method: 'GET',
        url: `/operational-access/runtime/people/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: agent.cookie },
      });
      expect(allowedRes.statusCode).toBe(200);
      const allowed = readJson<OperationalAccessRuntimePersonResponse>(allowedRes);
      expect(allowed.person.email).toBeNull();
      expect(allowed.person.fieldVisibility).toContainEqual({
        fieldKey: 'email',
        treatment: 'MASKED',
      });
      expect(allowed.decision.sourcePath).toContain('AGENT_GROUP_RESPONSIBLE_FOR');
      expect(allowed.decision.explanation.join(' ')).not.toContain('target@example.com');

      const otherRes = await app.inject({
        method: 'GET',
        url: `/operational-access/runtime/people/${other.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: agent.cookie },
      });
      expect(otherRes.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('enforces directed single-hop Oversight and explicit include-team behavior', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps);
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      const group = await createAgentGroup(deps, tenant.id);
      const managerA = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'AGENT',
      });
      const managerB = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const managerC = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const employeeB = await createMembership({ deps, tenantId: tenant.id, role: 'USER' });
      const employeeC = await createMembership({ deps, tenantId: tenant.id, role: 'USER' });

      for (const membershipId of [
        managerA.membershipId,
        managerB.membershipId,
        managerC.membershipId,
      ]) {
        await addGroupMember({ deps, tenantId: tenant.id, groupId: group.id, membershipId });
      }
      await addPersonalCardGrant({ deps, tenantId: tenant.id, groupId: group.id });
      await addResponsibleFor({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        agentMembershipId: managerB.membershipId,
        targetMembershipId: employeeB.membershipId,
      });
      await addResponsibleFor({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        agentMembershipId: managerC.membershipId,
        targetMembershipId: employeeC.membershipId,
      });

      const futureReview = new Date(Date.now() + 86_400_000).toISOString();
      const saveNoTeamRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/oversight',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: await advancedCoverageVersion(app, tenant.key, admin.cookie),
          entries: [
            {
              overseerMembershipId: managerA.membershipId,
              targetMembershipId: managerB.membershipId,
              includesResponsiblePeople: false,
              reason: 'Manager A reviews Manager B only.',
              reviewAt: futureReview,
            },
          ],
        },
      });
      expect(saveNoTeamRes.statusCode).toBe(200);

      const noTeamRes = await app.inject({
        method: 'GET',
        url: '/operational-access/runtime/people',
        headers: { host: hostForTenant(tenant.key), cookie: managerA.cookie },
      });
      expect(membershipIds(readJson<OperationalAccessRuntimePeopleResponse>(noTeamRes))).toEqual([
        managerB.membershipId,
      ]);

      const saveWithTeamRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/oversight',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: await advancedCoverageVersion(app, tenant.key, admin.cookie),
          entries: [
            {
              overseerMembershipId: managerA.membershipId,
              targetMembershipId: managerB.membershipId,
              includesResponsiblePeople: true,
              reason: 'Manager A reviews Manager B and assigned people.',
              reviewAt: futureReview,
            },
            {
              overseerMembershipId: managerB.membershipId,
              targetMembershipId: managerC.membershipId,
              includesResponsiblePeople: true,
              reason: 'Manager B reviews Manager C and assigned people.',
              reviewAt: futureReview,
            },
          ],
        },
      });
      expect(saveWithTeamRes.statusCode).toBe(200);

      const withTeamRes = await app.inject({
        method: 'GET',
        url: '/operational-access/runtime/people',
        headers: { host: hostForTenant(tenant.key), cookie: managerA.cookie },
      });
      expect(membershipIds(readJson<OperationalAccessRuntimePeopleResponse>(withTeamRes))).toEqual(
        [employeeB.membershipId, managerB.membershipId].sort(),
      );
      expect(
        membershipIds(readJson<OperationalAccessRuntimePeopleResponse>(withTeamRes)),
      ).not.toContain(employeeC.membershipId);

      const managerBCookie = await createCookieForMembership({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'AGENT',
        userId: managerB.userId,
        membershipId: managerB.membershipId,
      });

      const nonReciprocalRes = await app.inject({
        method: 'GET',
        url: `/operational-access/runtime/people/${managerA.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: managerBCookie },
      });
      expect(nonReciprocalRes.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('applies Temporary Coverage only within its active window', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps);
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      const group = await createAgentGroup(deps, tenant.id);
      const covering = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'AGENT',
      });
      const covered = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const target = await createMembership({ deps, tenantId: tenant.id, role: 'USER' });

      await addGroupMember({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        membershipId: covered.membershipId,
      });
      await addPersonalCardGrant({ deps, tenantId: tenant.id, groupId: group.id });
      await addResponsibleFor({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        agentMembershipId: covered.membershipId,
        targetMembershipId: target.membershipId,
      });

      const expiredRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/temporary-coverage',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: await advancedCoverageVersion(app, tenant.key, admin.cookie),
          entries: [
            {
              coveringMembershipId: covering.membershipId,
              coveredMembershipId: covered.membershipId,
              startsAt: new Date(Date.now() - 172_800_000).toISOString(),
              expiresAt: new Date(Date.now() - 86_400_000).toISOString(),
              reason: 'Past backup coverage.',
              reviewAt: null,
            },
          ],
        },
      });
      expect(expiredRes.statusCode).toBe(200);

      const expiredListRes = await app.inject({
        method: 'GET',
        url: '/operational-access/runtime/people',
        headers: { host: hostForTenant(tenant.key), cookie: covering.cookie },
      });
      expect(readJson<OperationalAccessRuntimePeopleResponse>(expiredListRes).people).toHaveLength(
        0,
      );

      const activeRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/temporary-coverage',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: await advancedCoverageVersion(app, tenant.key, admin.cookie),
          entries: [
            {
              coveringMembershipId: covering.membershipId,
              coveredMembershipId: covered.membershipId,
              startsAt: new Date(Date.now() - 60_000).toISOString(),
              expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
              reason: 'Active backup coverage.',
              reviewAt: null,
            },
          ],
        },
      });
      expect(activeRes.statusCode).toBe(200);

      const activeListRes = await app.inject({
        method: 'GET',
        url: '/operational-access/runtime/people',
        headers: { host: hostForTenant(tenant.key), cookie: covering.cookie },
      });
      expect(
        membershipIds(readJson<OperationalAccessRuntimePeopleResponse>(activeListRes)),
      ).toEqual([covered.membershipId, target.membershipId].sort());
    } finally {
      await close();
    }
  });

  it('requires Special Access metadata and grants only the explicit target until expiry', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps);
      const admin = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'ADMIN',
      });
      const agent = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'AGENT',
      });
      const target = await createMembership({ deps, tenantId: tenant.id, role: 'USER' });

      const invalidRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/special-access',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: await advancedCoverageVersion(app, tenant.key, admin.cookie),
          entries: [
            {
              membershipId: agent.membershipId,
              targetMembershipId: target.membershipId,
              actionKey: 'personal_cards.view',
              reason: '',
              reviewAt: new Date(Date.now() + 86_400_000).toISOString(),
              expiresAt: new Date(Date.now() + 172_800_000).toISOString(),
            },
          ],
        },
      });
      expect(invalidRes.statusCode).toBe(400);

      const validRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/special-access',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: await advancedCoverageVersion(app, tenant.key, admin.cookie),
          entries: [
            {
              membershipId: agent.membershipId,
              targetMembershipId: target.membershipId,
              actionKey: 'personal_cards.view',
              reason: 'Temporary sensitive review exception.',
              reviewAt: new Date(Date.now() + 86_400_000).toISOString(),
              expiresAt: new Date(Date.now() + 172_800_000).toISOString(),
            },
          ],
        },
      });
      expect(validRes.statusCode).toBe(200);

      const allowedRes = await app.inject({
        method: 'GET',
        url: `/operational-access/runtime/people/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: agent.cookie },
      });
      expect(allowedRes.statusCode).toBe(200);
      expect(
        readJson<OperationalAccessRuntimePersonResponse>(allowedRes).decision.sourcePath,
      ).toContain('SPECIAL_ACCESS');
    } finally {
      await close();
    }
  });
});
