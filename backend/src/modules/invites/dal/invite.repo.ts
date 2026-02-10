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
 */

import type { DbExecutor } from '../../../shared/db/db';

export class InviteRepo {
  constructor(private readonly db: DbExecutor) {}

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
}
