/**
 * backend/src/modules/invites/dal/invite.repo.ts
 *
 * WHY:
 * - DAL WRITES ONLY for invites (mutations).
 *
 * RULES:
 * - No transactions started here (service owns tx).
 * - No AppError.
 * - No policies.
 * - Supports withDb() for transaction binding (same pattern as AuditRepo).
 *
 * BRICK 12 UPDATE:
 * - Added insertInvite() for admin invite creation.
 * - Added cancelPendingInvitesByEmail() for bulk-cancel on resend.
 * - Added cancelInviteById() stub (implemented in PR2).
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { InviteRole } from '../invite.types';

export class InviteRepo {
  constructor(private readonly db: DbExecutor) {}

  /**
   * Returns a repo bound to a different executor (e.g. a transaction).
   * This keeps the "repo instance" pattern while supporting trx usage.
   */
  withDb(db: DbExecutor): InviteRepo {
    return new InviteRepo(db);
  }

  /**
   * Marks an invite as accepted only if still PENDING.
   * Returns true if updated, false if not (already used/cancelled/etc).
   */
  async markAccepted(params: { inviteId: string; usedAt: Date }): Promise<boolean> {
    const res = await this.db
      .updateTable('invites')
      .set({
        status: 'ACCEPTED',
        used_at: params.usedAt,
      })
      .where('id', '=', params.inviteId)
      .where('status', '=', 'PENDING')
      .executeTakeFirst();

    return Number(res?.numUpdatedRows ?? 0) > 0;
  }

  /**
   * Inserts a new PENDING invite row.
   * Returns the generated id and created_at timestamp.
   */
  async insertInvite(params: {
    tenantId: string;
    email: string;
    role: InviteRole;
    tokenHash: string;
    expiresAt: Date;
    createdByUserId: string;
  }): Promise<{ id: string; createdAt: Date }> {
    const row = await this.db
      .insertInto('invites')
      .values({
        tenant_id: params.tenantId,
        email: params.email,
        role: params.role,
        status: 'PENDING',
        token_hash: params.tokenHash,
        expires_at: params.expiresAt,
        created_by_user_id: params.createdByUserId,
      })
      .returning(['id', 'created_at'])
      .executeTakeFirstOrThrow();

    return { id: row.id, createdAt: row.created_at };
  }

  /**
   * Sets status='CANCELLED' and used_at=now() on all PENDING invites
   * for the given (tenantId, email) pair.
   *
   * Used by resendInvite to collapse any duplicate drift before inserting
   * a fresh invite. Returns the count of rows updated.
   */
  async cancelPendingInvitesByEmail(params: {
    tenantId: string;
    email: string;
    cancelledAt: Date;
  }): Promise<number> {
    const res = await this.db
      .updateTable('invites')
      .set({
        status: 'CANCELLED',
        used_at: params.cancelledAt,
      })
      .where('tenant_id', '=', params.tenantId)
      .where('email', '=', params.email)
      .where('status', '=', 'PENDING')
      .executeTakeFirst();

    return Number(res?.numUpdatedRows ?? 0);
  }
}
