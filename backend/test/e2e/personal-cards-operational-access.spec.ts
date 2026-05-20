import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';

import type { AppDeps } from '../../src/app/di';
import type { MembershipRole } from '../../src/modules/memberships/membership.types';
import type { OperationalAccessAdvancedCoverageResponse } from '../../src/modules/operational-access/operational-access.types';
import type {
  PersonalCardDetailResponse,
  PersonalCardsListResponse,
} from '../../src/modules/personal-cards/personal-cards.types';
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

function membershipIds(body: PersonalCardsListResponse): string[] {
  return body.cards.map((card) => card.membershipId).sort();
}

function fieldByKey(body: PersonalCardDetailResponse, fieldKey: string) {
  return body.card.fields.find((field) => field.fieldKey === fieldKey);
}

async function migrateForOperationalAccess(deps: AppDeps): Promise<void> {
  await upPeopleTeamsMigration(deps.db);
  await upOperationalAccessCapabilityMigration(deps.db);
  await upOperationalAccessGroupGrantsMigration(deps.db);
  await upOperationalAccessResolverMigration(deps.db);
  await upOperationalAccessAdvancedCoverageVersionsMigration(deps.db);
}

async function createTenant(deps: AppDeps, operationalAccessEnabled = true) {
  const key = `pc-oa-${randomUUID().slice(0, 8)}`;

  return deps.db
    .insertInto('tenants')
    .values({
      key,
      name: `Personal Cards OA Tenant ${key}`,
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
      email: (opts.email ?? `pc-oa-${randomUUID().slice(0, 8)}@example.com`).toLowerCase(),
      name: opts.name ?? `${opts.role} Personal Cards User`,
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

async function createSession(opts: {
  deps: AppDeps;
  tenantId: string;
  tenantKey: string;
  role: MembershipRole;
  email?: string;
}): Promise<{ cookie: string; userId: string; membershipId: string }> {
  const membership = await createMembership({
    deps: opts.deps,
    tenantId: opts.tenantId,
    role: opts.role,
    email: opts.email,
  });

  const cookie = await createCookieForMembership({
    deps: opts.deps,
    tenantId: opts.tenantId,
    tenantKey: opts.tenantKey,
    role: opts.role,
    userId: membership.userId,
    membershipId: membership.membershipId,
  });

  return { ...membership, cookie };
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
      name: `Personal Card Managers ${randomUUID().slice(0, 6)}`,
      normalized_name: `personal-card-managers-${randomUUID().slice(0, 8)}`,
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

describe('Personal Cards Operational Access integration', () => {
  it('uses backend-resolved OA for list/detail and never relies on frontend filtering', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps);
      const group = await createAgentGroup(deps, tenant.id);
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
        email: 'personal-target@example.com',
      });
      const other = await createMembership({ deps, tenantId: tenant.id, role: 'USER' });

      await addGroupMember({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        membershipId: agent.membershipId,
      });

      const memberOnlyRes = await app.inject({
        method: 'GET',
        url: '/personal/cards',
        headers: { host: hostForTenant(tenant.key), cookie: agent.cookie },
      });
      expect(memberOnlyRes.statusCode).toBe(200);
      expect(readJson<PersonalCardsListResponse>(memberOnlyRes).cards).toHaveLength(0);

      await addPersonalCardGrant({ deps, tenantId: tenant.id, groupId: group.id });
      const grantWithoutCoverageRes = await app.inject({
        method: 'GET',
        url: '/personal/cards',
        headers: { host: hostForTenant(tenant.key), cookie: agent.cookie },
      });
      expect(grantWithoutCoverageRes.statusCode).toBe(200);
      expect(readJson<PersonalCardsListResponse>(grantWithoutCoverageRes).cards).toHaveLength(0);

      await addResponsibleFor({
        deps,
        tenantId: tenant.id,
        groupId: group.id,
        agentMembershipId: agent.membershipId,
        targetMembershipId: target.membershipId,
      });

      const adminListRes = await app.inject({
        method: 'GET',
        url: '/personal/cards',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(adminListRes.statusCode).toBe(200);
      expect(membershipIds(readJson<PersonalCardsListResponse>(adminListRes))).toEqual(
        expect.arrayContaining([admin.membershipId, user.membershipId, agent.membershipId]),
      );

      const userListRes = await app.inject({
        method: 'GET',
        url: '/personal/cards',
        headers: { host: hostForTenant(tenant.key), cookie: user.cookie },
      });
      expect(userListRes.statusCode).toBe(200);
      expect(membershipIds(readJson<PersonalCardsListResponse>(userListRes))).toEqual([
        user.membershipId,
      ]);

      const agentListRes = await app.inject({
        method: 'GET',
        url: '/personal/cards',
        headers: { host: hostForTenant(tenant.key), cookie: agent.cookie },
      });
      expect(agentListRes.statusCode).toBe(200);
      expect(membershipIds(readJson<PersonalCardsListResponse>(agentListRes))).toEqual([
        target.membershipId,
      ]);

      const adminDetailRes = await app.inject({
        method: 'GET',
        url: `/personal/cards/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
      });
      expect(adminDetailRes.statusCode).toBe(200);
      const adminDetail = readJson<PersonalCardDetailResponse>(adminDetailRes);
      expect(fieldByKey(adminDetail, 'person.ssn')).toEqual(
        expect.objectContaining({
          fieldKey: 'person.ssn',
          sensitivity: 'SENSITIVE',
          treatment: 'VISIBLE',
        }),
      );
      expect(fieldByKey(adminDetail, 'person.date_of_birth')).toEqual(
        expect.objectContaining({
          fieldKey: 'person.date_of_birth',
          sensitivity: 'SENSITIVE',
          treatment: 'VISIBLE',
          value: '1970-01-01',
        }),
      );

      const allowedDetailRes = await app.inject({
        method: 'GET',
        url: `/personal/cards/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: agent.cookie },
      });
      expect(allowedDetailRes.statusCode).toBe(200);
      const allowedDetail = readJson<PersonalCardDetailResponse>(allowedDetailRes);
      expect(fieldByKey(allowedDetail, 'person.work_email')?.value).toBeNull();
      expect(allowedDetail.card.fieldVisibility).toContainEqual(
        expect.objectContaining({
          fieldKey: 'person.work_email',
          treatment: 'MASKED',
        }),
      );
      expect(fieldByKey(allowedDetail, 'person.ssn')).toEqual(
        expect.objectContaining({
          fieldKey: 'person.ssn',
          sensitivity: 'SENSITIVE',
          treatment: 'MASKED',
          value: 'MASKED',
        }),
      );
      expect(fieldByKey(allowedDetail, 'person.date_of_birth')).toEqual(
        expect.objectContaining({
          fieldKey: 'person.date_of_birth',
          sensitivity: 'SENSITIVE',
          treatment: 'HIDDEN',
          value: null,
        }),
      );
      expect(allowedDetail.card.fields.map((field) => field.fieldKey)).not.toContain(
        'person.personal_email',
      );
      expect(allowedDetail.card.sourcePath).toContain('AGENT_GROUP_RESPONSIBLE_FOR');
      expect(allowedDetail.card.explanation.join(' ')).not.toContain('personal-target@example.com');

      const unauthorizedDetailRes = await app.inject({
        method: 'GET',
        url: `/personal/cards/${other.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: agent.cookie },
      });
      expect(unauthorizedDetailRes.statusCode).toBe(403);

      const userBypassRes = await app.inject({
        method: 'GET',
        url: `/personal/cards/${target.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: user.cookie },
      });
      expect(userBypassRes.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('applies Oversight, Temporary Coverage, and Special Access through the real module route', async () => {
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
      const tempCovering = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'AGENT',
      });
      const specialAgent = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'AGENT',
      });

      for (const membershipId of [
        managerA.membershipId,
        managerB.membershipId,
        managerC.membershipId,
        tempCovering.membershipId,
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
      const noTeamRes = await app.inject({
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
      expect(noTeamRes.statusCode).toBe(200);

      const oversightNoTeamListRes = await app.inject({
        method: 'GET',
        url: '/personal/cards',
        headers: { host: hostForTenant(tenant.key), cookie: managerA.cookie },
      });
      expect(membershipIds(readJson<PersonalCardsListResponse>(oversightNoTeamListRes))).toEqual([
        managerB.membershipId,
      ]);

      const withTeamRes = await app.inject({
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
      expect(withTeamRes.statusCode).toBe(200);

      const oversightWithTeamListRes = await app.inject({
        method: 'GET',
        url: '/personal/cards',
        headers: { host: hostForTenant(tenant.key), cookie: managerA.cookie },
      });
      expect(membershipIds(readJson<PersonalCardsListResponse>(oversightWithTeamListRes))).toEqual(
        [employeeB.membershipId, managerB.membershipId].sort(),
      );
      expect(
        membershipIds(readJson<PersonalCardsListResponse>(oversightWithTeamListRes)),
      ).not.toContain(employeeC.membershipId);

      const tempExpiredRes = await app.inject({
        method: 'GET',
        url: `/personal/cards/${employeeB.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: tempCovering.cookie },
      });
      expect(tempExpiredRes.statusCode).toBe(403);

      const tempActiveSaveRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/temporary-coverage',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: await advancedCoverageVersion(app, tenant.key, admin.cookie),
          entries: [
            {
              coveringMembershipId: tempCovering.membershipId,
              coveredMembershipId: managerB.membershipId,
              startsAt: new Date(Date.now() - 60_000).toISOString(),
              expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
              reason: 'Active backup coverage.',
              reviewAt: null,
            },
          ],
        },
      });
      expect(tempActiveSaveRes.statusCode).toBe(200);

      const tempActiveRes = await app.inject({
        method: 'GET',
        url: `/personal/cards/${employeeB.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: tempCovering.cookie },
      });
      expect(tempActiveRes.statusCode).toBe(200);
      expect(readJson<PersonalCardDetailResponse>(tempActiveRes).card.sourcePath).toContain(
        'TEMPORARY_COVERAGE',
      );

      await deps.db
        .insertInto('tenant_oa_special_access')
        .values({
          tenant_id: tenant.id,
          membership_id: specialAgent.membershipId,
          target_membership_id: employeeC.membershipId,
          action_key: 'personal_cards.view',
          reason: 'Expired special access fixture.',
          review_at: new Date(Date.now() - 172_800_000),
          expires_at: new Date(Date.now() - 86_400_000),
          created_at: new Date(Date.now() - 259_200_000),
        })
        .execute();

      const expiredSpecialRes = await app.inject({
        method: 'GET',
        url: `/personal/cards/${employeeC.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: specialAgent.cookie },
      });
      expect(expiredSpecialRes.statusCode).toBe(403);

      const specialSaveRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/special-access',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: await advancedCoverageVersion(app, tenant.key, admin.cookie),
          entries: [
            {
              membershipId: specialAgent.membershipId,
              targetMembershipId: employeeC.membershipId,
              actionKey: 'personal_cards.view',
              reason: 'Temporary sensitive review exception.',
              reviewAt: new Date(Date.now() + 86_400_000).toISOString(),
              expiresAt: new Date(Date.now() + 172_800_000).toISOString(),
            },
          ],
        },
      });
      expect(specialSaveRes.statusCode).toBe(200);

      const specialAllowedRes = await app.inject({
        method: 'GET',
        url: `/personal/cards/${employeeC.membershipId}`,
        headers: { host: hostForTenant(tenant.key), cookie: specialAgent.cookie },
      });
      expect(specialAllowedRes.statusCode).toBe(200);
      expect(readJson<PersonalCardDetailResponse>(specialAllowedRes).card.sourcePath).toContain(
        'SPECIAL_ACCESS',
      );
    } finally {
      await close();
    }
  });

  it('fails closed when the OA capability is disabled for the tenant', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await migrateForOperationalAccess(deps);
      const tenant = await createTenant(deps, false);
      const user = await createSession({
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        role: 'USER',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/personal/cards',
        headers: { host: hostForTenant(tenant.key), cookie: user.cookie },
      });

      expect(res.statusCode).toBe(404);
    } finally {
      await close();
    }
  });
});
