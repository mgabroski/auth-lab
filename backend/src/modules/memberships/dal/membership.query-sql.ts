/**
 * backend/src/modules/memberships/dal/membership.query-sql.ts
 *
 * WHY:
 * - DAL READS ONLY for memberships (raw SQL access).
 * - Always tenant-scoped (membership belongs to a tenant).
 *
 * RULES:
 * - No AppError.
 * - No policies.
 * - No transactions started here.
 */

import type { Selectable } from 'kysely';
import type { DbExecutor } from '../../../shared/db/db';
import type { Memberships } from '../../../shared/db/database.types';

export type MembershipRow = Selectable<Memberships>;

export async function selectMembershipByTenantAndUserSql(
  db: DbExecutor,
  params: { tenantId: string; userId: string },
): Promise<MembershipRow | undefined> {
  return db
    .selectFrom('memberships')
    .selectAll()
    .where('tenant_id', '=', params.tenantId)
    .where('user_id', '=', params.userId)
    .executeTakeFirst();
}

export async function selectMembershipByIdSql(
  db: DbExecutor,
  membershipId: string,
): Promise<MembershipRow | undefined> {
  return db.selectFrom('memberships').selectAll().where('id', '=', membershipId).executeTakeFirst();
}
