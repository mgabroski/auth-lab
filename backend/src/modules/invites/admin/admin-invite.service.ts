/**
 * backend/src/modules/invites/admin/admin-invite.service.ts
 *
 * WHY:
 * - Thin facade for admin invite mutations. Each mutation method delegates
 *   to a flow that owns the transaction, rate limit, and two-phase audit.
 *
 * RULES:
 * - No transactions here — flows own orchestration boundaries (ER-18).
 * - No business logic — each mutation method is a one-liner (ER-16).
 * - listInvites is read-only and delegates directly to a query (ER-16b).
 * - Outbox enqueue is inside each flow's transaction.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { TokenHasher } from '../../../shared/security/token-hasher';
import type { RateLimiter } from '../../../shared/security/rate-limit';
import type { Logger } from '../../../shared/logger/logger';
import type { AuditRepo } from '../../../shared/audit/audit.repo';

import type { OutboxRepo } from '../../../shared/outbox/outbox.repo';
import type { OutboxEncryption } from '../../../shared/outbox/outbox-encryption';

import type { InviteRepo } from '../dal/invite.repo';
import type { InviteStatus, InviteSummary } from '../invite.types';
import { listInvitesByTenant } from '../queries/invite.queries';

import {
  executeCreateAdminInviteFlow,
  type CreateInviteFlowParams,
} from './flows/execute-create-admin-invite-flow';
import {
  executeResendAdminInviteFlow,
  type ResendInviteFlowParams,
} from './flows/execute-resend-admin-invite-flow';
import {
  executeCancelAdminInviteFlow,
  type CancelInviteFlowParams,
} from './flows/execute-cancel-admin-invite-flow';

export type CreateInviteParams = CreateInviteFlowParams;
export type ResendInviteParams = ResendInviteFlowParams;
export type CancelInviteParams = CancelInviteFlowParams;

export type ListInvitesParams = {
  tenantId: string;
  userId: string;
  status?: InviteStatus;
  limit: number;
  offset: number;
  requestId: string;
};

export class AdminInviteService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      tokenHasher: TokenHasher;
      rateLimiter: RateLimiter;
      logger: Logger;
      inviteRepo: InviteRepo;
      auditRepo: AuditRepo;
      outboxRepo: OutboxRepo;
      outboxEncryption: OutboxEncryption;
    },
  ) {}

  async createInvite(params: CreateInviteParams): Promise<InviteSummary> {
    return executeCreateAdminInviteFlow(this.deps, params);
  }

  async listInvites(
    params: ListInvitesParams,
  ): Promise<{ invites: InviteSummary[]; total: number }> {
    this.deps.logger.info({
      msg: 'admin-invite.list',
      flow: 'admin-invite.list',
      requestId: params.requestId,
      tenantId: params.tenantId,
      status: params.status ?? 'all',
      limit: params.limit,
      offset: params.offset,
    });

    return listInvitesByTenant(this.deps.db, {
      tenantId: params.tenantId,
      status: params.status,
      limit: params.limit,
      offset: params.offset,
    });
  }

  async resendInvite(params: ResendInviteParams): Promise<InviteSummary> {
    return executeResendAdminInviteFlow(this.deps, params);
  }

  async cancelInvite(params: CancelInviteParams): Promise<void> {
    return executeCancelAdminInviteFlow(this.deps, params);
  }
}
