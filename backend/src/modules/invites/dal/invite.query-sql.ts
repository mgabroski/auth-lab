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
 * - Added findPendingInviteByTenantAndEmailSql for duplicate-invite guard (PR1).
 * - Added findInviteByIdAndTenantSql for resend/cancel lookup (PR2).
 * - Added findInvitesByTenantSql + countInvitesByTenantSql for paginated list (PR2).
 *
 * PHASE 1B UPDATE:
 * - Added findLatestInviteByTenantAndEmailSql so auth flows can resolve the
 *   current invite-state input for a tenant-entry decision without relying on a
 *   token-specific route.
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

/**
 * Returns the most-recently-created invite for (tenantId, email), regardless of
 * terminal status. Used by auth-entry policy resolution so runtime flows can
 * distinguish VALID vs EXPIRED vs ONE_TIME_USED invite state.
 */
export async function findLatestInviteByTenantAndEmailSql(
  db: DbExecutor,
  params: { tenantId: string; email: string },
): Promise<InviteRow | undefined> {
  return db
    .selectFrom('invites')
    .selectAll()
    .where('tenant_id', '=', params.tenantId)
    .where('email', '=', params.email)
    .orderBy('created_at', 'desc')
    .limit(1)
    .executeTakeFirst();
}

/**
 * Returns a single invite scoped to (inviteId, tenantId).
 * Used by resend and cancel to load the target invite before mutation.
 * Tenant scoping is the security boundary — cross-tenant reads return undefined.
 */
export async function findInviteByIdAndTenantSql(
  db: DbExecutor,
  params: { inviteId: string; tenantId: string },
): Promise<InviteRow | undefined> {
  return db
    .selectFrom('invites')
    .selectAll()
    .where('id', '=', params.inviteId)
    .where('tenant_id', '=', params.tenantId)
    .executeTakeFirst();
}

/**
 * Returns a page of invite rows for a tenant, newest first.
 * Optional status filter narrows to a single status value.
 */
export async function findInvitesByTenantSql(
  db: DbExecutor,
  params: {
    tenantId: string;
    status?: string;
    limit: number;
    offset: number;
  },
): Promise<InviteRow[]> {
  return db
    .selectFrom('invites')
    .selectAll()
    .where('tenant_id', '=', params.tenantId)
    .$if(params.status !== undefined, (qb) => qb.where('status', '=', params.status!))
    .orderBy('created_at', 'desc')
    .limit(params.limit)
    .offset(params.offset)
    .execute();
}

/**
 * Returns the total count of invites for a tenant.
 * Matches the same optional status filter as findInvitesByTenantSql so that
 * the list endpoint can return accurate totals for filtered queries.
 */
export async function countInvitesByTenantSql(
  db: DbExecutor,
  params: {
    tenantId: string;
    status?: string;
  },
): Promise<number> {
  const result = await db
    .selectFrom('invites')
    .select((eb) => eb.fn.count('id').as('total'))
    .where('tenant_id', '=', params.tenantId)
    .$if(params.status !== undefined, (qb) => qb.where('status', '=', params.status!))
    .executeTakeFirstOrThrow();

  return Number(result.total);
}
