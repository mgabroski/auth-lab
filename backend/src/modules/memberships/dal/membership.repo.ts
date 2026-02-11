/**
 * backend/src/modules/memberships/dal/membership.repo.ts
 *
 * WHY:
 * - DAL WRITES ONLY for memberships (mutations).
 * - Always tenant-scoped (membership belongs to a tenant).
 *
 * RULES:
 * - No transactions started here (service owns tx).
 * - No AppError.
 * - No policies.
 * - Supports withDb() for transaction binding.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { MembershipRole, MembershipStatus } from '../membership.types';

export class MembershipRepo {
  constructor(private readonly db: DbExecutor) {}

  withDb(db: DbExecutor): MembershipRepo {
    return new MembershipRepo(db);
  }

  /**
   * Creates a new membership. Unique constraint (tenant_id, user_id) enforced by DB.
   */
  async insertMembership(params: {
    tenantId: string;
    userId: string;
    role: MembershipRole;
    status: MembershipStatus;
    invitedAt: Date;
  }): Promise<{ id: string }> {
    const row = await this.db
      .insertInto('memberships')
      .values({
        tenant_id: params.tenantId,
        user_id: params.userId,
        role: params.role,
        status: params.status,
        invited_at: params.invitedAt,
      })
      .returning(['id'])
      .executeTakeFirstOrThrow();

    return { id: row.id };
  }

  /**
   * Activates a membership only if current status is INVITED.
   * Idempotency guard: WHERE status = 'INVITED'.
   * Returns true if updated, false if already active/suspended.
   */
  async activateMembership(params: { membershipId: string; acceptedAt: Date }): Promise<boolean> {
    const res = await this.db
      .updateTable('memberships')
      .set({
        status: 'ACTIVE',
        accepted_at: params.acceptedAt,
      })
      .where('id', '=', params.membershipId)
      .where('status', '=', 'INVITED')
      .executeTakeFirst();

    return Number(res?.numUpdatedRows ?? 0) > 0;
  }

  /**
   * Suspends a membership. Only ACTIVE → SUSPENDED.
   * Future-ready (admin actions, Brick 12+).
   */
  async suspendMembership(params: { membershipId: string; suspendedAt: Date }): Promise<boolean> {
    const res = await this.db
      .updateTable('memberships')
      .set({
        status: 'SUSPENDED',
        suspended_at: params.suspendedAt,
      })
      .where('id', '=', params.membershipId)
      .where('status', '=', 'ACTIVE')
      .executeTakeFirst();

    return Number(res?.numUpdatedRows ?? 0) > 0;
  }
}
