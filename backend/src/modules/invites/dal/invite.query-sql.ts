/**
 * backend/src/modules/invites/dal/invite.query-sql.ts
 *
 * WHY:
 * - DAL READS ONLY for invites (raw SQL access).
 *
 * RULES:
 * - No AppError.
 * - No policies.
 * - No transactions started here.
 * - Tenant-scoped reads where applicable.
 *
 * BRICK 12 UPDATE:
 * - Added findPendingInviteByTenantAndEmailSql for duplicate-invite guard.
 */

import type { Selectable } from 'kysely';
import type { DbExecutor } from '../../../shared/db/db';
import type { Invites } from '../../../shared/db/database.types';

export type InviteRow = Selectable<Invites>;

export async function findInviteByTenantAndTokenHashSql(
  db: DbExecutor,
  params: { tenantId: string; tokenHash: string },
): Promise<InviteRow | undefined> {
  return db
    .selectFrom('invites')
    .selectAll()
    .where('tenant_id', '=', params.tenantId)
    .where('token_hash', '=', params.tokenHash)
    .executeTakeFirst();
}

/**
 * Returns the most-recently-created PENDING invite for (tenantId, email).
 * Used by createInvite to detect duplicate-pending before inserting.
 */
export async function findPendingInviteByTenantAndEmailSql(
  db: DbExecutor,
  params: { tenantId: string; email: string },
): Promise<InviteRow | undefined> {
  return db
    .selectFrom('invites')
    .selectAll()
    .where('tenant_id', '=', params.tenantId)
    .where('email', '=', params.email)
    .where('status', '=', 'PENDING')
    .orderBy('created_at', 'desc')
    .limit(1)
    .executeTakeFirst();
}
