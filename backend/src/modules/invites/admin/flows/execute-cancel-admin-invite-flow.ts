/**
 * src/modules/invites/admin/flows/execute-cancel-admin-invite-flow.ts
 *
 * WHY:
 * - cancelInvite owns a transaction, rate limit, and two-phase audit.
 *   Per ER-18 these responsibilities belong in a flow, not a service.
 *
 * RULES:
 * - Rate limit before db.transaction() (ER-19).
 * - Success audit inside transaction (ER-38).
 * - Failure audit in catch using bare auditRepo (ER-39).
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { Logger } from '../../../../shared/logger/logger';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';

import type { InviteRepo } from '../../dal/invite.repo';
import { ADMIN_INVITE_RATE_LIMITS } from '../../invite.constants';
import { getInviteByIdAndTenant } from '../../queries/invite.queries';
import { auditInviteCancelled, auditInviteCancelFailed } from '../../invite.audit';

import { AdminInviteErrors } from '../admin-invite.errors';

export type CancelInviteFlowParams = {
  inviteId: string;
  tenantId: string;
  userId: string;
  requestId: string;
  ip: string;
  userAgent: string | null;
};

type FailureCtx = { reason: string };

export async function executeCancelAdminInviteFlow(
  deps: {
    db: DbExecutor;
    tokenHasher: TokenHasher;
    rateLimiter: RateLimiter;
    logger: Logger;
    inviteRepo: InviteRepo;
    auditRepo: AuditRepo;
  },
  params: CancelInviteFlowParams,
): Promise<void> {
  // ── Rate limit — before any DB work (ER-19) ──────────────────────────
  await deps.rateLimiter.hitOrThrow({
    key: `admin-invite-cancel:tenant:${params.tenantId}:user:${params.userId}`,
    ...ADMIN_INVITE_RATE_LIMITS.cancelInvite.perAdminPerTenant,
  });

  let failureCtx: FailureCtx | null = null;

  try {
    await deps.db.transaction().execute(async (trx) => {
      const inviteRepo = deps.inviteRepo.withDb(trx);

      // ── Success audit writer — bound to trx (ER-38) ──────────────────
      const audit = new AuditWriter(deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: params.tenantId, userId: params.userId });

      const existing = await getInviteByIdAndTenant(trx, {
        inviteId: params.inviteId,
        tenantId: params.tenantId,
      });
      if (!existing) {
        failureCtx = { reason: 'invite_not_found' };
        throw AdminInviteErrors.inviteNotFound();
      }

      if (existing.status !== 'PENDING') {
        failureCtx = { reason: 'invite_not_cancellable' };
        throw AdminInviteErrors.inviteNotCancellable();
      }

      const cancelled = await inviteRepo.cancelInviteById({
        inviteId: params.inviteId,
        tenantId: params.tenantId,
        cancelledAt: new Date(),
      });
      if (!cancelled) {
        failureCtx = { reason: 'invite_concurrent_cancel' };
        throw AdminInviteErrors.inviteNotCancellable();
      }

      // ── Success audit — inside tx (ER-38) ────────────────────────────
      await auditInviteCancelled(audit, {
        id: params.inviteId,
        email: existing.email,
        role: existing.role,
      });
    });
  } catch (err) {
    // ── Failure audit — bare auditRepo, outside tx (ER-39) ───────────
    if (failureCtx) {
      const ctx = failureCtx as FailureCtx;
      const failAudit = new AuditWriter(deps.auditRepo, {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: params.tenantId, userId: params.userId, membershipId: null });
      await auditInviteCancelFailed(failAudit, { reason: ctx.reason });
    }
    throw err;
  }

  deps.logger.info({
    msg: 'admin-invite.cancel.success',
    flow: 'admin-invite.cancel',
    requestId: params.requestId,
    tenantId: params.tenantId,
    inviteId: params.inviteId,
  });
}
