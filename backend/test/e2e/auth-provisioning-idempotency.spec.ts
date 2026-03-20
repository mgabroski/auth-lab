import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';

import type { DbExecutor } from '../../src/shared/db/db';
import { buildTestApp } from '../helpers/build-test-app';
import { provisionUserToTenant } from '../../src/modules/_shared/use-cases/provision-user-to-tenant.usecase';
import { UserRepo } from '../../src/modules/users/dal/user.repo';
import { MembershipRepo } from '../../src/modules/memberships/dal/membership.repo';

type InsertMembershipIfAbsentParams = Parameters<MembershipRepo['insertMembershipIfAbsent']>[0];
type InsertMembershipIfAbsentResult = Awaited<
  ReturnType<MembershipRepo['insertMembershipIfAbsent']>
>;

async function createTenant(
  db: DbExecutor,
  tenantKey: string,
): Promise<{ id: string; key: string }> {
  return db
    .insertInto('tenants')
    .values({
      key: tenantKey,
      name: `Tenant ${tenantKey}`,
      is_active: true,
      public_signup_enabled: true,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

/**
 * Test-only barrier repo.
 *
 * WHY:
 * - The race we want to prove happens after both callers have already read
 *   "no membership exists yet" and then try to insert the same row.
 * - This repo pauses the first insertMembershipIfAbsent() caller until the
 *   second caller reaches the same method. That makes the conflict path
 *   deterministic instead of probabilistic.
 */
class BarrierMembershipRepo extends MembershipRepo {
  private arrivals = 0;
  private readonly gate: Promise<void>;
  private releaseGate!: () => void;

  constructor(db: DbExecutor) {
    super(db);
    this.gate = new Promise<void>((resolve) => {
      this.releaseGate = resolve;
    });
  }

  withDb(db: DbExecutor): MembershipRepo {
    return new BarrierMembershipRepo(db);
  }

  async insertMembershipIfAbsent(
    params: InsertMembershipIfAbsentParams,
  ): Promise<InsertMembershipIfAbsentResult> {
    this.arrivals += 1;

    if (this.arrivals === 1) {
      await this.gate;
    } else if (this.arrivals === 2) {
      this.releaseGate();
    }

    return super.insertMembershipIfAbsent(params);
  }
}

describe('auth provisioning idempotency', () => {
  it('concurrent provisioning creates one user and one membership without surfacing a unique-violation error', async () => {
    const { deps, close } = await buildTestApp();

    try {
      const tenantKey = `t-${randomUUID().slice(0, 10)}`;
      const tenant = await createTenant(deps.db, tenantKey);

      const email = `race-${randomUUID().slice(0, 8)}@example.com`;
      const now = new Date();

      const userRepo = new UserRepo(deps.db);
      const membershipRepo = new BarrierMembershipRepo(deps.db);

      const [first, second] = await Promise.all([
        provisionUserToTenant({
          trx: deps.db,
          userRepo,
          membershipRepo,
          email,
          name: 'Race User',
          tenantId: tenant.id,
          role: 'MEMBER',
          now,
        }),
        provisionUserToTenant({
          trx: deps.db,
          userRepo,
          membershipRepo,
          email,
          name: 'Race User',
          tenantId: tenant.id,
          role: 'MEMBER',
          now,
        }),
      ]);

      // Both callers should converge on the same logical identity.
      expect(first.user.id).toBe(second.user.id);
      expect(first.membership.id).toBe(second.membership.id);

      // Exactly one call created the membership; the other observed the existing row.
      expect(Number(first.membershipCreated) + Number(second.membershipCreated)).toBe(1);

      // No activation path here — both calls target a brand-new ACTIVE membership.
      expect(first.membershipActivated).toBe(false);
      expect(second.membershipActivated).toBe(false);

      const users = await deps.db
        .selectFrom('users')
        .select(['id', 'email'])
        .where('email', '=', email.toLowerCase())
        .execute();

      expect(users).toHaveLength(1);

      const memberships = await deps.db
        .selectFrom('memberships')
        .select(['id', 'tenant_id', 'user_id', 'role', 'status'])
        .where('tenant_id', '=', tenant.id)
        .where('user_id', '=', users[0].id)
        .execute();

      expect(memberships).toHaveLength(1);
      expect(memberships[0].id).toBe(first.membership.id);
      expect(memberships[0].role).toBe('MEMBER');
      expect(memberships[0].status).toBe('ACTIVE');
    } finally {
      await close();
    }
  });
});
