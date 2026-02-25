/**
 * backend/src/modules/audit/dal/audit.queries.ts
 *
 * WHY:
 * - Typed wrappers over the raw SQL functions in audit.query-sql.ts.
 * - Service calls these functions; never calls query-sql directly.
 * - Lives in src/modules/audit/dal/ — NOT in src/shared/audit/ (Comment C locked).
 *
 * RULES:
 * - No business logic here.
 * - No AppError here.
 * - Pass-through with typed params and return values only.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { AuditEventDto } from '../admin-audit.schemas';
import {
  selectAuditEventsByTenantSql,
  countAuditEventsByTenantSql,
  type AuditEventsFilter,
  type AuditEventsCountFilter,
} from './audit.query-sql';

function rowToDto(
  row: Awaited<ReturnType<typeof selectAuditEventsByTenantSql>>[number],
): AuditEventDto {
  return {
    id: row.id,
    action: row.action,
    userId: row.user_id,
    membershipId: row.membership_id,
    requestId: row.request_id,
    ip: row.ip,
    userAgent: row.user_agent,
    metadata: (row.metadata ?? {}) as Record<string, unknown>,
    createdAt: row.created_at.toISOString(),
  };
}

export async function listAuditEvents(
  db: DbExecutor,
  params: AuditEventsFilter,
): Promise<AuditEventDto[]> {
  const rows = await selectAuditEventsByTenantSql(db, params);
  return rows.map(rowToDto);
}

export async function countAuditEvents(
  db: DbExecutor,
  params: AuditEventsCountFilter,
): Promise<number> {
  return countAuditEventsByTenantSql(db, params);
}
