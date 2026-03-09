/**
 * src/modules/invites/admin/flows/execute-create-admin-invite-flow.ts
 *
 * WHY:
 * - createInvite owns a transaction, rate limit, and two-phase audit.
 *   Per ER-18 these responsibilities belong in a flow, not a service.
 *
 * RULES:
 * - Rate limit before db.transaction() (ER-19).
 * - Success audit inside transaction (ER-38).
 * - Failure audit in catch using bare auditRepo (ER-39).
 * - Outbox enqueue inside same transaction as invite row insert.
 * - tokenHash never returned in InviteSummary.
 * - No membership pre-creation (Decision C — locked).
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { Logger } from '../../../../shared/logger/logger';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import { AppError } from '../../../../shared/http/errors';

import type { OutboxRepo } from '../../../../shared/outbox/outbox.repo';
import type { OutboxEncryption } from '../../../../shared/outbox/outbox-encryption';

import type { InviteRepo } from '../../dal/invite.repo';
import type { InviteRole, InviteSummary } from '../../invite.types';
import { ADMIN_INVITE_RATE_LIMITS, INVITE_TTL_DAYS } from '../../invite.constants';
import { getPendingInviteByTenantAndEmail } from '../../queries/invite.queries';
import { auditInviteCreated, auditInviteCreateFailed } from '../../invite.audit';

import { getTenantById, isEmailDomainAllowed, assertTenantIsActive } from '../../../tenants';
import { getUserByEmail } from '../../../users';
import { getMembershipByTenantAndUser } from '../../../memberships';

import { AdminInviteErrors } from '../admin-invite.errors';
import { generateSecureToken } from '../../../../shared/security/token';

export type CreateInviteFlowParams = {
  tenantId: string;
  userId: string;
  tenantKey: string;
  email: string;
  role: InviteRole;
  requestId: string;
  ip: string;
  userAgent: string | null;
};

type FailureCtx = { reason: string };

export async function executeCreateAdminInviteFlow(
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
  params: CreateInviteFlowParams,
): Promise<InviteSummary> {
  // ── Rate limit — before any DB work (ER-19) ──────────────────────────
  await deps.rateLimiter.hitOrThrow({
    key: `admin-invite-create:tenant:${params.tenantId}:user:${params.userId}`,
    ...ADMIN_INVITE_RATE_LIMITS.createInvite.perAdminPerTenant,
  });

  const email = params.email.toLowerCase();

  let failureCtx: FailureCtx | null = null;
  let summary: InviteSummary | null = null;

  try {
    const result = await deps.db.transaction().execute(async (trx) => {
      const inviteRepo = deps.inviteRepo.withDb(trx);

      // ── Success audit writer — bound to trx (ER-38) ──────────────────
      const audit = new AuditWriter(deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: params.tenantId, userId: params.userId });

      const tenant = await getTenantById(trx, params.tenantId);
      if (!tenant) {
        failureCtx = { reason: 'tenant_not_found' };
        throw AppError.notFound('Tenant not found.');
      }
      assertTenantIsActive(tenant);

      if (!isEmailDomainAllowed(tenant, email)) {
        failureCtx = { reason: 'email_domain_not_permitted' };
        throw AdminInviteErrors.emailDomainNotPermitted();
      }

      const existingPending = await getPendingInviteByTenantAndEmail(trx, {
        tenantId: params.tenantId,
        email,
      });
      if (existingPending) {
        failureCtx = { reason: 'invite_already_exists' };
        throw AdminInviteErrors.inviteAlreadyExists();
      }

      const existingUser = await getUserByEmail(trx, email);
      if (existingUser) {
        const membership = await getMembershipByTenantAndUser(trx, {
          tenantId: params.tenantId,
          userId: existingUser.id,
        });
        if (membership) {
          if (membership.status === 'ACTIVE') {
            failureCtx = { reason: 'email_already_member' };
            throw AdminInviteErrors.emailAlreadyMember();
          }
          if (membership.status === 'SUSPENDED') {
            failureCtx = { reason: 'email_suspended' };
            throw AdminInviteErrors.emailSuspended();
          }
        }
      }

      const rawToken = generateSecureToken();
      const tokenHash = deps.tokenHasher.hash(rawToken);
      const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000);

      const inserted = await inviteRepo.insertInvite({
        tenantId: params.tenantId,
        email,
        role: params.role,
        tokenHash,
        expiresAt,
        createdByUserId: params.userId,
      });

      // ── Success audit — inside tx (ER-38) ────────────────────────────
      await auditInviteCreated(audit, {
        id: inserted.id,
        email,
        role: params.role,
        createdByUserId: params.userId,
      });

      const payload = deps.outboxEncryption.encryptPayload({
        token: rawToken,
        toEmail: email,
        tenantKey: params.tenantKey,
        inviteId: inserted.id,
        role: params.role,
      });

      await deps.outboxRepo.enqueueWithinTx(trx, {
        type: 'invite.created',
        payload,
        idempotencyKey: `invite-created:${inserted.id}:${tokenHash}`,
      });

      const s: InviteSummary = {
        id: inserted.id,
        tenantId: params.tenantId,
        email,
        role: params.role,
        status: 'PENDING',
        expiresAt,
        usedAt: null,
        createdAt: inserted.createdAt,
        createdByUserId: params.userId,
      };

      return { summary: s };
    });

    summary = result.summary;
  } catch (err) {
    // ── Failure audit — bare auditRepo, outside tx (ER-39) ───────────
    if (failureCtx) {
      const ctx = failureCtx as FailureCtx;
      const failAudit = new AuditWriter(deps.auditRepo, {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: params.tenantId, userId: params.userId, membershipId: null });
      await auditInviteCreateFailed(failAudit, { reason: ctx.reason });
    }
    throw err;
  }

  deps.logger.info({
    msg: 'admin-invite.create.success',
    flow: 'admin-invite.create',
    requestId: params.requestId,
    tenantId: params.tenantId,
    inviteId: summary.id,
    role: params.role,
  });

  return summary;
}
