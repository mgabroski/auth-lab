import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';

import type { AppDeps } from '../../src/app/di';
import type { MembershipRole } from '../../src/modules/memberships/membership.types';
import type { OperationalAccessAdvancedCoverageResponse } from '../../src/modules/operational-access/operational-access.types';
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
  const key = `oa-gov-${randomUUID().slice(0, 8)}`;

  return deps.db
    .insertInto('tenants')
    .values({
      key,
      name: `OA Governance Tenant ${key}`,
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
}): Promise<{ cookie: string; userId: string; membershipId: string }> {
  const user = await opts.deps.db
    .insertInto('users')
    .values({
      email: `${opts.role.toLowerCase()}-${randomUUID().slice(0, 8)}@example.com`,
      name: `${opts.role} Governance User`,
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
}): Promise<{ userId: string; membershipId: string }> {
  const user = await opts.deps.db
    .insertInto('users')
    .values({
      email: `${opts.role.toLowerCase()}-${randomUUID().slice(0, 8)}@example.com`,
      name: `${opts.role} Governance Target`,
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

describe('operational access governance hardening', () => {
  it('uses subject-scoped advanced coverage saves and records before/after audit details', async () => {
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
      const managerA = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const managerB = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const managerC = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const managerD = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const futureReview = new Date(Date.now() + 86_400_000).toISOString();

      const saveARes = await app.inject({
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
              reason: 'Manager A reviews Manager B.',
              reviewAt: futureReview,
            },
          ],
        },
      });
      expect(saveARes.statusCode).toBe(200);

      const saveCRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/oversight',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: await advancedCoverageVersion(app, tenant.key, admin.cookie),
          entries: [
            {
              overseerMembershipId: managerC.membershipId,
              targetMembershipId: managerD.membershipId,
              includesResponsiblePeople: false,
              reason: 'Manager C reviews Manager D.',
              reviewAt: futureReview,
            },
          ],
        },
      });
      expect(saveCRes.statusCode).toBe(200);

      const rows = await deps.db
        .selectFrom('tenant_oa_oversight')
        .select(['overseer_membership_id', 'target_membership_id'])
        .where('tenant_id', '=', tenant.id)
        .execute();

      expect(rows).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            overseer_membership_id: managerA.membershipId,
            target_membership_id: managerB.membershipId,
          }),
          expect.objectContaining({
            overseer_membership_id: managerC.membershipId,
            target_membership_id: managerD.membershipId,
          }),
        ]),
      );

      const audit = await deps.db
        .selectFrom('audit_events')
        .select(['tenant_id', 'user_id', 'membership_id', 'action', 'metadata', 'created_at'])
        .where('tenant_id', '=', tenant.id)
        .where('action', '=', 'operational_access.oversight_saved')
        .orderBy('created_at', 'desc')
        .executeTakeFirstOrThrow();

      expect(audit.user_id).toBe(admin.userId);
      expect(audit.membership_id).toBe(admin.membershipId);
      const auditMetadata = audit.metadata as {
        source?: unknown;
        runtimeVisibilityChanged?: unknown;
        before?: unknown;
        after?: unknown;
        replaceForMembershipIds?: unknown;
      };

      expect(auditMetadata).toEqual(
        expect.objectContaining({
          source: 'OperationalAccessService.saveOversight',
          runtimeVisibilityChanged: true,
          replaceForMembershipIds: [managerC.membershipId],
        }),
      );
      expect(Array.isArray(auditMetadata.before)).toBe(true);
      expect(Array.isArray(auditMetadata.after)).toBe(true);
    } finally {
      await close();
    }
  });

  it('writes failure audit for rejected sensitive advanced coverage mutations', async () => {
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
      const agent = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const user = await createMembership({ deps, tenantId: tenant.id, role: 'USER' });

      const rejectedRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/oversight',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: await advancedCoverageVersion(app, tenant.key, admin.cookie),
          entries: [
            {
              overseerMembershipId: agent.membershipId,
              targetMembershipId: user.membershipId,
              includesResponsiblePeople: false,
              reason: 'Invalid oversight target should be rejected.',
              reviewAt: new Date(Date.now() + 86_400_000).toISOString(),
            },
          ],
        },
      });

      expect(rejectedRes.statusCode).toBe(400);

      const failureAudit = await deps.db
        .selectFrom('audit_events')
        .select(['tenant_id', 'user_id', 'membership_id', 'action', 'metadata'])
        .where('tenant_id', '=', tenant.id)
        .where('action', '=', 'operational_access.oversight_save_failed')
        .executeTakeFirstOrThrow();

      expect(failureAudit.user_id).toBe(admin.userId);
      expect(failureAudit.membership_id).toBe(admin.membershipId);
      const failureAuditMetadata = failureAudit.metadata as {
        source?: unknown;
        runtimeVisibilityChanged?: unknown;
        requestedEntryCount?: unknown;
        error?: { message?: unknown };
      };

      expect(failureAuditMetadata).toEqual(
        expect.objectContaining({
          source: 'OperationalAccessService.saveOversight',
          runtimeVisibilityChanged: false,
          requestedEntryCount: 1,
        }),
      );
      expect(typeof failureAuditMetadata.error?.message).toBe('string');
    } finally {
      await close();
    }
  });

  it('rejects stale advanced coverage saves with a 409 version conflict', async () => {
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
      const managerA = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const managerB = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const managerC = await createMembership({ deps, tenantId: tenant.id, role: 'AGENT' });
      const futureReview = new Date(Date.now() + 86_400_000).toISOString();
      const staleVersion = await advancedCoverageVersion(app, tenant.key, admin.cookie);

      const firstSaveRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/oversight',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: staleVersion,
          entries: [
            {
              overseerMembershipId: managerA.membershipId,
              targetMembershipId: managerB.membershipId,
              includesResponsiblePeople: false,
              reason: 'Manager A reviews Manager B.',
              reviewAt: futureReview,
            },
          ],
        },
      });
      expect(firstSaveRes.statusCode).toBe(200);
      expect(readJson<OperationalAccessAdvancedCoverageResponse>(firstSaveRes).version).toBe(
        staleVersion + 1,
      );

      const staleSaveRes = await app.inject({
        method: 'PUT',
        url: '/operational-access/advanced-coverage/oversight',
        headers: { host: hostForTenant(tenant.key), cookie: admin.cookie },
        payload: {
          expectedVersion: staleVersion,
          entries: [
            {
              overseerMembershipId: managerA.membershipId,
              targetMembershipId: managerC.membershipId,
              includesResponsiblePeople: false,
              reason: 'Stale save must not overwrite current coverage.',
              reviewAt: futureReview,
            },
          ],
        },
      });
      expect(staleSaveRes.statusCode).toBe(409);

      const rows = await deps.db
        .selectFrom('tenant_oa_oversight')
        .select(['overseer_membership_id', 'target_membership_id'])
        .where('tenant_id', '=', tenant.id)
        .execute();

      expect(rows).toEqual([
        expect.objectContaining({
          overseer_membership_id: managerA.membershipId,
          target_membership_id: managerB.membershipId,
        }),
      ]);
    } finally {
      await close();
    }
  });
});
