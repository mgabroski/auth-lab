/**
 * backend/src/modules/audit/admin-audit.service.ts
 *
 * WHY:
 * - Orchestrates audit event listing: pagination, filtering, tenant isolation.
 * - Single responsibility: read-only query path for the audit viewer.
 *
 * RULES:
 * - No transactions — read-only operation, no mutations.
 * - No rate limit — admin-only endpoint, session guard is sufficient.
 * - tenant_id always sourced from session, never from request params.
 * - Delegates all DB access to dal/audit.queries.ts — no raw DB here.
 */

import type { DbExecutor } from '../../shared/db/db';
import type { AuditEventDto } from './admin-audit.schemas';
import { listAuditEvents, countAuditEvents } from './dal/audit.queries';

export type ListAuditEventsParams = {
  tenantId: string;
  action?: string;
  userId?: string;
  from?: string;
  to?: string;
  limit: number;
  offset: number;
};

export type ListAuditEventsResult = {
  events: AuditEventDto[];
  total: number;
  limit: number;
  offset: number;
};

export class AdminAuditService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
    },
  ) {}

  async listEvents(params: ListAuditEventsParams): Promise<ListAuditEventsResult> {
    const filter = {
      tenantId: params.tenantId,
      action: params.action,
      userId: params.userId,
      from: params.from,
      to: params.to,
    };

    const [events, total] = await Promise.all([
      listAuditEvents(this.deps.db, { ...filter, limit: params.limit, offset: params.offset }),
      countAuditEvents(this.deps.db, filter),
    ]);

    return {
      events,
      total,
      limit: params.limit,
      offset: params.offset,
    };
  }
}
