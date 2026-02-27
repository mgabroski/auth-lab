/**
 * backend/src/modules/invites/admin/admin-invite.service.ts
 *
 * WHY:
 * - Orchestrates all admin invite mutations: create, list, resend, cancel.
 * - Follows the same transaction-in-service pattern as InviteService (no flows/ subfolder).
 * - PR2: email delivery is durable via DB Outbox.
 *
 * RULES:
 * - Only place allowed to open transactions for admin invite operations.
 * - No raw DB access — uses queries/ and dal/ only.
 * - Rate limit before transaction (before any DB work).
 * - Audit inside transaction (success audits commit atomically with data).
 * - Outbox enqueue is inside the same transaction as invite row insert.
 * - tokenHash never returned in InviteSummary responses.
 * - No membership pre-creation (Decision C — locked).
 * - Outbox payload must never store raw email/token (tokenEnc + toEmailEnc only).
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { TokenHasher } from '../../../shared/security/token-hasher';
import type { RateLimiter } from '../../../shared/security/rate-limit';
import type { Logger } from '../../../shared/logger/logger';
import type { AuditRepo } from '../../../shared/audit/audit.repo';
import type { Queue } from '../../../shared/messaging/queue';
import { AuditWriter } from '../../../shared/audit/audit.writer';
import { AppError } from '../../../shared/http/errors';

import type { OutboxRepo } from '../../../shared/outbox/outbox.repo';
import type { OutboxEncryption } from '../../../shared/outbox/outbox-encryption';

import type { InviteRepo } from '../dal/invite.repo';
import type { InviteRole, InviteStatus, InviteSummary } from '../invite.types';
import { ADMIN_INVITE_RATE_LIMITS, INVITE_TTL_DAYS } from '../invite.constants';
import {
  getPendingInviteByTenantAndEmail,
  getInviteByIdAndTenant,
  listInvitesByTenant,
} from '../queries/invite.queries';
import { auditInviteCreated, auditInviteCancelled, auditInviteResent } from '../invite.audit';

import { getTenantById, isEmailDomainAllowed, assertTenantIsActive } from '../../tenants';
import { getUserByEmail } from '../../users';
import { getMembershipByTenantAndUser } from '../../memberships';

import { AdminInviteErrors } from './admin-invite.errors';
import { generateSecureToken } from '../../../shared/security/token';

// ── Param types ──────────────────────────────────────────────────────────────

export type CreateInviteParams = {
  tenantId: string;
  userId: string;
  tenantKey: string;
  email: string;
  role: InviteRole;
  requestId: string;
  ip: string;
  userAgent: string | null;
};

export type ListInvitesParams = {
  tenantId: string;
  userId: string;
  status?: InviteStatus;
  limit: number;
  offset: number;
  requestId: string;
};

export type ResendInviteParams = {
  inviteId: string;
  tenantId: string;
  userId: string;
  tenantKey: string;
  requestId: string;
  ip: string;
  userAgent: string | null;
};

export type CancelInviteParams = {
  inviteId: string;
  tenantId: string;
  userId: string;
  requestId: string;
  ip: string;
  userAgent: string | null;
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
      queue: Queue;

      // Outbox (PR2)
      outboxRepo: OutboxRepo;
      outboxEncryption: OutboxEncryption;
    },
  ) {}

  async createInvite(params: CreateInviteParams): Promise<InviteSummary> {
    // ── Step 1: Rate limit — before any DB work ───────────────────────────────
    await this.deps.rateLimiter.hitOrThrow({
      key: `admin-invite-create:tenant:${params.tenantId}:user:${params.userId}`,
      ...ADMIN_INVITE_RATE_LIMITS.createInvite.perAdminPerTenant,
    });

    // ── Step 2: Normalize email ───────────────────────────────────────────────
    const email = params.email.toLowerCase();

    // ── Steps 3–11: inside transaction ───────────────────────────────────────
    const { summary } = await this.deps.db.transaction().execute(async (trx) => {
      const inviteRepo = this.deps.inviteRepo.withDb(trx);

      const audit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: params.tenantId, userId: params.userId });

      // Step 3: Load tenant, assert active.
      const tenant = await getTenantById(trx, params.tenantId);
      if (!tenant) {
        throw AppError.notFound('Tenant not found.');
      }
      assertTenantIsActive(tenant);

      // Step 4: Email domain check
      if (!isEmailDomainAllowed(tenant, email)) {
        throw AdminInviteErrors.emailDomainNotPermitted();
      }

      // Step 5: Duplicate pending invite check
      const existingPending = await getPendingInviteByTenantAndEmail(trx, {
        tenantId: params.tenantId,
        email,
      });
      if (existingPending) {
        throw AdminInviteErrors.inviteAlreadyExists();
      }

      // Step 6: Membership check (only if user already exists in the system)
      const existingUser = await getUserByEmail(trx, email);
      if (existingUser) {
        const membership = await getMembershipByTenantAndUser(trx, {
          tenantId: params.tenantId,
          userId: existingUser.id,
        });
        if (membership) {
          if (membership.status === 'ACTIVE') throw AdminInviteErrors.emailAlreadyMember();
          if (membership.status === 'SUSPENDED') throw AdminInviteErrors.emailSuspended();
        }
      }

      // Step 7: Generate token
      const rawToken = generateSecureToken();
      const tokenHash = this.deps.tokenHasher.hash(rawToken);
      const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000);

      // Step 8: Insert invite row
      const inserted = await inviteRepo.insertInvite({
        tenantId: params.tenantId,
        email,
        role: params.role,
        tokenHash,
        expiresAt,
        createdByUserId: params.userId,
      });

      // Step 9 (Decision C — locked): No membership pre-creation.

      // Step 10: Audit inside transaction
      await auditInviteCreated(audit, {
        id: inserted.id,
        email,
        role: params.role,
        createdByUserId: params.userId,
      });

      // Step 11: Outbox enqueue INSIDE transaction (durable)
      const payload = this.deps.outboxEncryption.encryptPayload({
        token: rawToken,
        toEmail: email,
        tenantKey: params.tenantKey,
        inviteId: inserted.id,
        role: params.role,
      });

      await this.deps.outboxRepo.enqueueWithinTx(trx, {
        type: 'invite.created',
        payload,
        idempotencyKey: `invite-created:${inserted.id}:${tokenHash}`,
      });

      const summary: InviteSummary = {
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

      return { summary };
    });

    this.deps.logger.info({
      msg: 'admin-invite.create.success',
      flow: 'admin-invite.create',
      requestId: params.requestId,
      tenantId: params.tenantId,
      inviteId: summary.id,
      role: params.role,
    });

    return summary;
  }

  /**
   * Returns a paginated list of invites for the caller's tenant.
   * No transaction needed — read-only operation.
   */
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

  /**
   * Bulk-cancels ALL pending invites for (tenantId, email), then inserts a new
   * invite row and re-sends the invite email.
   *
   * Returns the new InviteSummary (new ID, new token, same email/role/tenant).
   *
   * WHY bulk-cancel:
   * - The spec requires "one active invite at a time" per (tenant, email).
   * - Drift can cause multiple PENDING rows to exist (e.g. from a previous resend
   *   that partially failed). Bulk-cancel collapses all of them atomically.
   * - The old approach (cancel only by inviteId) left any other PENDING invites
   *   for the same email alive — creating extra valid entry points.
   *
   * SECURITY:
   * - Tenant-scoped lookup prevents cross-tenant resend.
   * - cancelPendingInvitesByEmail uses WHERE status='PENDING' as a TOCTOU guard.
   * - Outbox enqueue occurs within the same transaction as the new invite insert.
   */
  async resendInvite(params: ResendInviteParams): Promise<InviteSummary> {
    await this.deps.rateLimiter.hitOrThrow({
      key: `admin-invite-resend:tenant:${params.tenantId}:user:${params.userId}`,
      ...ADMIN_INVITE_RATE_LIMITS.resendInvite.perAdminPerTenant,
    });

    const { newSummary } = await this.deps.db.transaction().execute(async (trx) => {
      const inviteRepo = this.deps.inviteRepo.withDb(trx);

      const audit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: params.tenantId, userId: params.userId });

      const existing = await getInviteByIdAndTenant(trx, {
        inviteId: params.inviteId,
        tenantId: params.tenantId,
      });
      if (!existing) {
        throw AdminInviteErrors.inviteNotFound();
      }

      if (existing.status !== 'PENDING') {
        throw AdminInviteErrors.inviteNotResendable();
      }

      const now = new Date();
      const cancelledCount = await inviteRepo.cancelPendingInvitesByEmail({
        tenantId: params.tenantId,
        email: existing.email,
        cancelledAt: now,
      });
      if (cancelledCount === 0) {
        throw AdminInviteErrors.inviteNotResendable();
      }

      const rawToken = generateSecureToken();
      const tokenHash = this.deps.tokenHasher.hash(rawToken);
      const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000);

      const newRow = await inviteRepo.insertInvite({
        tenantId: params.tenantId,
        email: existing.email,
        role: existing.role,
        tokenHash,
        expiresAt,
        createdByUserId: params.userId,
      });

      await auditInviteResent(audit, {
        oldInviteId: params.inviteId,
        newInviteId: newRow.id,
        email: existing.email,
        role: existing.role,
      });

      const payload = this.deps.outboxEncryption.encryptPayload({
        token: rawToken,
        toEmail: existing.email,
        tenantKey: params.tenantKey,
        inviteId: newRow.id,
        role: existing.role,
      });

      await this.deps.outboxRepo.enqueueWithinTx(trx, {
        type: 'invite.created',
        payload,
        idempotencyKey: `invite-resent:${newRow.id}:${tokenHash}`,
      });

      const newSummary: InviteSummary = {
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

      return { newSummary };
    });

    this.deps.logger.info({
      msg: 'admin-invite.resend.success',
      flow: 'admin-invite.resend',
      requestId: params.requestId,
      tenantId: params.tenantId,
      oldInviteId: params.inviteId,
      newInviteId: newSummary.id,
    });

    return newSummary;
  }

  /**
   * Cancels a PENDING invite by ID.
   *
   * SECURITY:
   * - Tenant-scoped lookup prevents cross-tenant cancel.
   * - cancelInviteById uses WHERE status='PENDING' as a TOCTOU guard.
   */
  async cancelInvite(params: CancelInviteParams): Promise<void> {
    await this.deps.db.transaction().execute(async (trx) => {
      const inviteRepo = this.deps.inviteRepo.withDb(trx);

      const audit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: params.tenantId, userId: params.userId });

      const existing = await getInviteByIdAndTenant(trx, {
        inviteId: params.inviteId,
        tenantId: params.tenantId,
      });
      if (!existing) {
        throw AdminInviteErrors.inviteNotFound();
      }

      if (existing.status !== 'PENDING') {
        throw AdminInviteErrors.inviteNotCancellable();
      }

      const cancelled = await inviteRepo.cancelInviteById({
        inviteId: params.inviteId,
        tenantId: params.tenantId,
        cancelledAt: new Date(),
      });
      if (!cancelled) {
        throw AdminInviteErrors.inviteNotCancellable();
      }

      await auditInviteCancelled(audit, {
        id: params.inviteId,
        email: existing.email,
        role: existing.role,
      });
    });

    this.deps.logger.info({
      msg: 'admin-invite.cancel.success',
      flow: 'admin-invite.cancel',
      requestId: params.requestId,
      tenantId: params.tenantId,
      inviteId: params.inviteId,
    });
  }
}
