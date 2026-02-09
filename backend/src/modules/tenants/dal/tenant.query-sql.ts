import type { Selectable } from 'kysely';
import type { DbExecutor } from '../../../shared/db/db';
import type { Tenants } from '../../../shared/db/database.types';

/**
 * DAL READS ONLY
 * - No AppError
 * - No policies
 * - No transactions started here
 */
export type TenantRow = Selectable<Tenants>;

export async function findTenantByKeySql(
  db: DbExecutor,
  tenantKey: string,
): Promise<TenantRow | undefined> {
  return db.selectFrom('tenants').selectAll().where('key', '=', tenantKey).executeTakeFirst();
}
