/**
 * src/modules/invites/admin/flows/execute-resend-admin-invite-flow.ts
 *
 * WHY:
 * - resendInvite owns a transaction, rate limit, and two-phase audit.
 *   Per ER-18 these responsibilities belong in a flow, not a service.
 *
 * RULES:
 * - Rate limit before db.transaction() (ER-19).
 * - Success audit inside transaction (ER-38).
 * - Failure audit in catch using bare auditRepo (ER-39).
 * - Outbox enqueue inside same transaction as new invite row.
 * - tokenHash never returned in InviteSummary.
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { Logger } from '../../../../shared/logger/logger';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';

import type { OutboxRepo } from '../../../../shared/outbox/outbox.repo';
import type { OutboxEncryption } from '../../../../shared/outbox/outbox-encryption';

import type { InviteRepo } from '../../dal/invite.repo';
import type { InviteSummary } from '../../invite.types';
import { ADMIN_INVITE_RATE_LIMITS, INVITE_TTL_DAYS } from '../../invite.constants';
import { getInviteByIdAndTenant } from '../../queries/invite.queries';
import { auditInviteResent, auditInviteResendFailed } from '../../invite.audit';

import { AdminInviteErrors } from '../admin-invite.errors';
import { generateSecureToken } from '../../../../shared/security/token';

export type ResendInviteFlowParams = {
  inviteId: string;
  tenantId: string;
  userId: string;
  tenantKey: string;
  requestId: string;
  ip: string;
  userAgent: string | null;
};

type FailureCtx = { reason: string };

export async function executeResendAdminInviteFlow(
  deps: {
    db: DbExecutor;
    tokenHasher: TokenHasher;
    rateLimiter: RateLimiter;
    logger: Logger;
    inviteRepo: InviteRepo;
    auditRepo: AuditRepo;
    outboxRepo: OutboxRepo;
    outboxEncryption: OutboxEncryption;
  },
  params: ResendInviteFlowParams,
): Promise<InviteSummary> {
  // ── Rate limit — before any DB work (ER-19) ──────────────────────────
  await deps.rateLimiter.hitOrThrow({
    key: `admin-invite-resend:tenant:${params.tenantId}:user:${params.userId}`,
    ...ADMIN_INVITE_RATE_LIMITS.resendInvite.perAdminPerTenant,
  });

  let failureCtx: FailureCtx | null = null;
  let newSummary: InviteSummary | null = null;

  try {
    const result = await deps.db.transaction().execute(async (trx) => {
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
        failureCtx = { reason: 'invite_not_resendable' };
        throw AdminInviteErrors.inviteNotResendable();
      }

      const now = new Date();
      const cancelledCount = await inviteRepo.cancelPendingInvitesByEmail({
        tenantId: params.tenantId,
        email: existing.email,
        cancelledAt: now,
      });
      if (cancelledCount === 0) {
        failureCtx = { reason: 'invite_cancel_failed' };
        throw AdminInviteErrors.inviteNotResendable();
      }

      const rawToken = generateSecureToken();
      const tokenHash = deps.tokenHasher.hash(rawToken);
      const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000);

      const newRow = await inviteRepo.insertInvite({
        tenantId: params.tenantId,
        email: existing.email,
        role: existing.role,
        tokenHash,
        expiresAt,
        createdByUserId: params.userId,
      });

      // ── Success audit — inside tx (ER-38) ────────────────────────────
      await auditInviteResent(audit, {
        oldInviteId: params.inviteId,
        newInviteId: newRow.id,
        email: existing.email,
        role: existing.role,
      });

      const payload = deps.outboxEncryption.encryptPayload({
        token: rawToken,
        toEmail: existing.email,
        tenantKey: params.tenantKey,
        inviteId: newRow.id,
        role: existing.role,
      });

      await deps.outboxRepo.enqueueWithinTx(trx, {
        type: 'invite.created',
        payload,
        idempotencyKey: `invite-resent:${newRow.id}:${tokenHash}`,
      });

      const s: InviteSummary = {
        id: newRow.id,
        tenantId: params.tenantId,
        email: existing.email,
        role: existing.role,
        status: 'PENDING',
        expiresAt,
        usedAt: null,
        createdAt: newRow.createdAt,
        createdByUserId: params.userId,
      };

      return { newSummary: s };
    });

    newSummary = result.newSummary;
  } catch (err) {
    // ── Failure audit — bare auditRepo, outside tx (ER-39) ───────────
    if (failureCtx) {
      const ctx = failureCtx as FailureCtx;
      const failAudit = new AuditWriter(deps.auditRepo, {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: params.tenantId, userId: params.userId, membershipId: null });
      await auditInviteResendFailed(failAudit, { reason: ctx.reason });
    }
    throw err;
  }

  deps.logger.info({
    msg: 'admin-invite.resend.success',
    flow: 'admin-invite.resend',
    requestId: params.requestId,
    tenantId: params.tenantId,
    oldInviteId: params.inviteId,
    newInviteId: newSummary.id,
  });

  return newSummary;
}
