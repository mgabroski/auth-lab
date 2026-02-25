/**
 * backend/src/modules/audit/dal/audit.query-sql.ts
 *
 * WHY:
 * - Provides raw Kysely query implementations for audit event reads.
 * - Lives in src/modules/audit/dal/ — NOT in src/shared/audit/ which is
 *   writer-only infrastructure (Comment C locked).
 *
 * RULES:
 * - No business logic here — only typed SQL construction.
 * - tenant_id filter is ALWAYS applied — never nullable. Tenant isolation
 *   is enforced at the query layer, not the caller's responsibility.
 * - ORDER BY created_at DESC, id DESC — locked for pagination determinism.
 * - Optional filters (action, userId, from, to) applied via .$if() only
 *   when the param is defined.
 * - Never select token_hash, password_hash, or any credential fields.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { JsonValue } from '../../../shared/db/database.types';

export type AuditEventRow = {
  id: string;
  action: string;
  user_id: string | null;
  membership_id: string | null;
  request_id: string | null;
  ip: string | null;
  user_agent: string | null;
  metadata: JsonValue;
  created_at: Date;
};

export type AuditEventsFilter = {
  tenantId: string;
  action?: string;
  userId?: string;
  from?: string;
  to?: string;
  limit: number;
  offset: number;
};

export async function selectAuditEventsByTenantSql(
  db: DbExecutor,
  params: AuditEventsFilter,
): Promise<AuditEventRow[]> {
  return db
    .selectFrom('audit_events')
    .select([
      'id',
      'action',
      'user_id',
      'membership_id',
      'request_id',
      'ip',
      'user_agent',
      'metadata',
      'created_at',
    ])
    .where('tenant_id', '=', params.tenantId)
    .$if(params.action !== undefined, (qb) => qb.where('action', '=', params.action!))
    .$if(params.userId !== undefined, (qb) => qb.where('user_id', '=', params.userId!))
    .$if(params.from !== undefined, (qb) => qb.where('created_at', '>=', new Date(params.from!)))
    .$if(params.to !== undefined, (qb) => qb.where('created_at', '<=', new Date(params.to!)))
    .orderBy('created_at', 'desc')
    .orderBy('id', 'desc')
    .limit(params.limit)
    .offset(params.offset)
    .execute() as Promise<AuditEventRow[]>;
}

export type AuditEventsCountFilter = Omit<AuditEventsFilter, 'limit' | 'offset'>;

export async function countAuditEventsByTenantSql(
  db: DbExecutor,
  params: AuditEventsCountFilter,
): Promise<number> {
  const result = await db
    .selectFrom('audit_events')
    .select((eb) => eb.fn.countAll<string>().as('count'))
    .where('tenant_id', '=', params.tenantId)
    .$if(params.action !== undefined, (qb) => qb.where('action', '=', params.action!))
    .$if(params.userId !== undefined, (qb) => qb.where('user_id', '=', params.userId!))
    .$if(params.from !== undefined, (qb) => qb.where('created_at', '>=', new Date(params.from!)))
    .$if(params.to !== undefined, (qb) => qb.where('created_at', '<=', new Date(params.to!)))
    .executeTakeFirstOrThrow();

  return parseInt(result.count, 10);
}
