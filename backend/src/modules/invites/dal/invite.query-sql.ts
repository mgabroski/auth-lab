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
