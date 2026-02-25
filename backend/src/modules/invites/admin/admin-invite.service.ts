/**
 * backend/src/modules/invites/admin/admin-invite.service.ts
 *
 * WHY:
 * - Orchestrates all admin invite mutations: create, list, resend, cancel.
 * - Follows the same transaction-in-service pattern as InviteService (no flows/ subfolder).
 *
 * RULES:
 * - Only place allowed to open transactions for admin invite operations.
 * - No raw DB access — uses queries/ and dal/ only.
 * - Rate limit before transaction (before any DB work).
 * - Audit inside transaction (success audits commit atomically with data).
 * - Enqueue outside transaction (fire-and-forget; survives rollback independently).
 * - tokenHash never returned in InviteSummary responses.
 * - No membership pre-creation (Decision C — locked).
 *
 * PR1: createInvite.
 * PR2: listInvites, resendInvite, cancelInvite.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { TokenHasher } from '../../../shared/security/token-hasher';
import type { RateLimiter } from '../../../shared/security/rate-limit';
import type { Logger } from '../../../shared/logger/logger';
import type { AuditRepo } from '../../../shared/audit/audit.repo';
import type { Queue } from '../../../shared/messaging/queue';
import { AuditWriter } from '../../../shared/audit/audit.writer';

import type { InviteRepo } from '../dal/invite.repo';
import type { InviteRole, InviteStatus, InviteSummary } from '../invite.types';
import { ADMIN_INVITE_RATE_LIMITS, INVITE_TTL_DAYS } from '../invite.constants';
import {
  getPendingInviteByTenantAndEmail,
  getInviteByIdAndTenant,
  listInvitesByTenant,
} from '../queries/invite.queries';
import { auditInviteCreated, auditInviteCancelled, auditInviteResent } from '../invite.audit';

import { getTenantById, isEmailDomainAllowed } from '../../tenants';
import { getUserByEmail } from '../../users';
import { getMembershipByTenantAndUser } from '../../memberships';

import { assertTenantIsActive } from '../../tenants/policies/tenant-safety.policy';
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

// ── Service ───────────────────────────────────────────────────────────────────

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
    },
  ) {}

  // ── PR1: createInvite ──────────────────────────────────────────────────────

  async createInvite(params: CreateInviteParams): Promise<InviteSummary> {
    // ── Step 1: Rate limit — before any DB work ───────────────────────────────
    await this.deps.rateLimiter.hitOrThrow({
      key: `admin-invite-create:tenant:${params.tenantId}:user:${params.userId}`,
      ...ADMIN_INVITE_RATE_LIMITS.createInvite.perAdminPerTenant,
    });

    // ── Step 2: Normalize email ───────────────────────────────────────────────
    const email = params.email.toLowerCase();

    // ── Steps 3–9: inside transaction ────────────────────────────────────────
    const { summary, rawToken } = await this.deps.db.transaction().execute(async (trx) => {
      const inviteRepo = this.deps.inviteRepo.withDb(trx);

      const audit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: params.tenantId, userId: params.userId });

      // Step 3: Load tenant, assert active
      const tenant = await getTenantById(trx, params.tenantId);
      if (!tenant) {
        throw AdminInviteErrors.inviteNotFound({ reason: 'tenant_not_found' });
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
          if (membership.status === 'ACTIVE') {
            throw AdminInviteErrors.emailAlreadyMember();
          }
          if (membership.status === 'SUSPENDED') {
            throw AdminInviteErrors.emailSuspended();
          }
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

      this.deps.logger.info({
        msg: 'admin-invite.create.success',
        flow: 'admin-invite.create',
        requestId: params.requestId,
        tenantId: params.tenantId,
        inviteId: inserted.id,
        role: params.role,
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

      return { summary, rawToken };
    });

    // ── Step 11: Enqueue outside transaction ──────────────────────────────────
    await this.deps.queue.enqueue({
      type: 'admin.invite-email',
      inviteId: summary.id,
      email: summary.email,
      role: summary.role,
      inviteToken: rawToken,
      tenantKey: params.tenantKey,
    });

    return summary;
  }

  // ── PR2: listInvites ──────────────────────────────────────────────────────

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

  // ── PR2: resendInvite ─────────────────────────────────────────────────────

  /**
   * Cancels the specified PENDING invite, generates a new token, inserts a new
   * invite row, and re-sends the invite email.
   *
   * Returns the new InviteSummary (new ID, new token, same email/role/tenant).
   *
   * SECURITY:
   * - Tenant-scoped lookup prevents cross-tenant resend.
   * - cancelInviteById uses WHERE status='PENDING' as a TOCTOU guard: if two
   *   concurrent resend requests race, one gets 0 rows updated and the service
   *   throws inviteNotResendable.
   * - rawToken never stored; enqueued only after the transaction commits.
   */
  async resendInvite(params: ResendInviteParams): Promise<InviteSummary> {
    // Rate limit before any DB work
    await this.deps.rateLimiter.hitOrThrow({
      key: `admin-invite-resend:tenant:${params.tenantId}:user:${params.userId}`,
      ...ADMIN_INVITE_RATE_LIMITS.resendInvite.perAdminPerTenant,
    });

    const { newSummary, rawToken } = await this.deps.db.transaction().execute(async (trx) => {
      const inviteRepo = this.deps.inviteRepo.withDb(trx);

      const audit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({ tenantId: params.tenantId, userId: params.userId });

      // Step 1: Load invite — tenant scope is the security boundary
      const existing = await getInviteByIdAndTenant(trx, {
        inviteId: params.inviteId,
        tenantId: params.tenantId,
      });
      if (!existing) {
        throw AdminInviteErrors.inviteNotFound();
      }

      // Step 2: Assert PENDING (preflight check — TOCTOU guard happens at step 3)
      if (existing.status !== 'PENDING') {
        throw AdminInviteErrors.inviteNotResendable();
      }

      // Step 3: Cancel old invite atomically — WHERE status='PENDING' is the TOCTOU guard
      const cancelled = await inviteRepo.cancelInviteById({
        inviteId: params.inviteId,
        tenantId: params.tenantId,
        cancelledAt: new Date(),
      });
      if (!cancelled) {
        // Lost the race — another request cancelled it between our read and this write
        throw AdminInviteErrors.inviteNotResendable();
      }

      // Step 4: Generate new token + expiry
      const rawToken = generateSecureToken();
      const tokenHash = this.deps.tokenHasher.hash(rawToken);
      const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000);

      // Step 5: Insert new invite row (same email, role, tenant — new ID + token)
      const newRow = await inviteRepo.insertInvite({
        tenantId: params.tenantId,
        email: existing.email,
        role: existing.role,
        tokenHash,
        expiresAt,
        createdByUserId: params.userId,
      });

      // Step 6: Audit inside transaction
      await auditInviteResent(audit, {
        oldInviteId: params.inviteId,
        newInviteId: newRow.id,
        email: existing.email,
        role: existing.role,
      });

      this.deps.logger.info({
        msg: 'admin-invite.resend.success',
        flow: 'admin-invite.resend',
        requestId: params.requestId,
        tenantId: params.tenantId,
        oldInviteId: params.inviteId,
        newInviteId: newRow.id,
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

      return { newSummary, rawToken };
    });

    // Enqueue outside transaction — fire-and-forget
    await this.deps.queue.enqueue({
      type: 'admin.invite-email',
      inviteId: newSummary.id,
      email: newSummary.email,
      role: newSummary.role,
      inviteToken: rawToken,
      tenantKey: params.tenantKey,
    });

    return newSummary;
  }

  // ── PR2: cancelInvite ─────────────────────────────────────────────────────

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

      // Step 1: Load invite — tenant scope is the security boundary
      const existing = await getInviteByIdAndTenant(trx, {
        inviteId: params.inviteId,
        tenantId: params.tenantId,
      });
      if (!existing) {
        throw AdminInviteErrors.inviteNotFound();
      }

      // Step 2: Assert PENDING (preflight check)
      if (existing.status !== 'PENDING') {
        throw AdminInviteErrors.inviteNotCancellable();
      }

      // Step 3: Cancel atomically — TOCTOU guard via WHERE status='PENDING'
      const cancelled = await inviteRepo.cancelInviteById({
        inviteId: params.inviteId,
        tenantId: params.tenantId,
        cancelledAt: new Date(),
      });
      if (!cancelled) {
        throw AdminInviteErrors.inviteNotCancellable();
      }

      // Step 4: Audit inside transaction
      await auditInviteCancelled(audit, {
        id: params.inviteId,
        email: existing.email,
        role: existing.role,
      });

      this.deps.logger.info({
        msg: 'admin-invite.cancel.success',
        flow: 'admin-invite.cancel',
        requestId: params.requestId,
        tenantId: params.tenantId,
        inviteId: params.inviteId,
      });
    });
  }
}
