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
 * PR1: createInvite only.
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
import type { InviteRole, InviteSummary } from '../invite.types';
import { ADMIN_INVITE_RATE_LIMITS, INVITE_TTL_DAYS } from '../invite.constants';
import { getPendingInviteByTenantAndEmail } from '../queries/invite.queries';
import { auditInviteCreated } from '../invite.audit';

import { getTenantById, isEmailDomainAllowed } from '../../tenants';
import { getUserByEmail } from '../../users';
import { getMembershipByTenantAndUser } from '../../memberships';

import { assertTenantIsActive } from '../../tenants/policies/tenant-safety.policy';
import { AdminInviteErrors } from './admin-invite.errors';

import { generateSecureToken } from '../../../shared/security/token';

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
        // Should never happen — session already validated tenantId at login.
        // Guard defensively to prevent runtime NPE.
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
          // INVITED status is already implied by the pending invite check above.
          // A stale INVITED membership without a PENDING invite is a data anomaly;
          // we allow the invite in this case to avoid blocking the admin.
        }
      }

      // Step 7: Generate token outside the query but inside the transaction boundary.
      // rawToken never stored — passed to queue after tx commits.
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

      // Step 9 (Decision C — locked): Do NOT create a membership row here.
      // Membership is created during registration when the user finalises their account.

      // Step 10: Audit inside transaction (Rule B — success audits commit atomically)
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

    // ── Step 11: Enqueue outside transaction — fire-and-forget ───────────────
    // rawToken captured before tx commit; survives rollback independently.
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
}
