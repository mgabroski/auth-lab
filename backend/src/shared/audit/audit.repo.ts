/**
 * backend/src/shared/audit/audit.repo.ts
 *
 * WHY:
 * - Append-only audit writer (DB persistence).
 * - Services call this when "user did something meaningful".
 *
 * RULES:
 * - DAL-style component: DB concerns only.
 * - No business rules here.
 * - No AppError.
 * - Must work with both DB and transactions (DbExecutor).
 * - Metadata is accepted as plain object and serialized here.
 */

import type { DbExecutor } from '../db/db';
import type { JsonValue } from '../db/database.types';
import type { AuditEventInsert } from './audit.types';

function toJsonValue(input: unknown): JsonValue {
  // Ensures:
  // - no functions / symbols
  // - strips undefined
  // - guarantees JSON-serializable value
  return JSON.parse(JSON.stringify(input ?? {})) as JsonValue;
}

export class AuditRepo {
  constructor(private readonly db: DbExecutor) {}

  /**
   * Returns a repo bound to a different executor (e.g. a transaction).
   * This keeps the "repo instance" pattern while supporting trx usage.
   */
  withDb(db: DbExecutor): AuditRepo {
    return new AuditRepo(db);
  }

  async append(event: AuditEventInsert): Promise<void> {
    await this.db
      .insertInto('audit_events')
      .values({
        action: event.action,
        tenant_id: event.tenantId,
        user_id: event.userId,
        membership_id: event.membershipId,
        request_id: event.requestId,
        ip: event.ip,
        user_agent: event.userAgent,
        metadata: toJsonValue(event.metadata ?? {}),
        // created_at is Generated in DB
      })
      .execute();
  }
}
