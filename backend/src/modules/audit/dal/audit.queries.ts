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

// Even though this is an admin-only endpoint, audit metadata can contain
// token-like or credential-like values that must never be returned.
const SENSITIVE_KEYS = new Set(['tokenHash', 'passwordHash', 'credentials']);

function sanitizeMetadata(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sanitizeMetadata);
  if (value && typeof value === 'object') {
    const input = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input)) {
      if (SENSITIVE_KEYS.has(k)) continue;
      out[k] = sanitizeMetadata(v);
    }
    return out;
  }
  return value;
}

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
    metadata: sanitizeMetadata(row.metadata ?? {}) as Record<string, unknown>,
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
