/**
 * backend/src/modules/invites/invite.service.ts
 *
 * WHY:
 * - Orchestrates invite acceptance end-to-end (Brick 6).
 * - Only place allowed to start transactions.
 *
 * RULES:
 * - No raw DB access outside queries/DAL.
 * - Enforce tenant safety here.
 * - Never store/log raw tokens (hash immediately).
 * - Audit meaningful actions to DB (append-only).
 */

import type { DbExecutor } from '../../shared/db/db';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { Logger } from '../../shared/logger/logger';
import type { AuditRepo } from '../../shared/audit/audit.repo';

import {
  assertTenantExists,
  assertTenantIsActive,
  assertTenantKeyPresent,
} from '../tenants/policies/tenant-safety.policy';
import { getTenantByKey } from '../tenants/tenant.queries';

import { getInviteByTenantAndTokenHash } from './invite.queries';
import {
  assertInviteBelongsToTenant,
  assertInviteExists,
  assertInviteIsPending,
  assertInviteNotExpired,
} from './policies/invite.policy';
import { InviteErrors } from './invite.errors';

import type { InviteRepo } from './dal/invite.repo';

export type AcceptInviteParams = {
  tenantKey: string | null;
  token: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export type AcceptInviteResult = {
  status: 'ACCEPTED';
  nextAction: 'SET_PASSWORD' | 'SIGN_IN' | 'MFA_SETUP_REQUIRED';
};

export class InviteService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      tokenHasher: TokenHasher;
      logger: Logger;
      inviteRepo: InviteRepo;
      auditRepo: AuditRepo;
    },
  ) {}

  async acceptInvite(params: AcceptInviteParams): Promise<AcceptInviteResult> {
    const now = new Date();

    this.deps.logger.info({
      msg: 'invites.accept.start',
      flow: 'invites.accept',
      requestId: params.requestId,
      tenantKey: params.tenantKey,
      ip: params.ip,
    });

    return this.deps.db.transaction().execute(async (trx) => {
      // bind audit repo to trx (append-only within same tx boundary)
      const auditRepo = this.deps.auditRepo.withDb(trx);

      // 1) Tenant boundary (LOCKED)
      assertTenantKeyPresent(params.tenantKey);

      const tenant = await getTenantByKey(trx, params.tenantKey);
      assertTenantExists(tenant, params.tenantKey);
      assertTenantIsActive(tenant);

      // 2) Hash token immediately (never store raw token)
      const tokenHash = this.deps.tokenHasher.hash(params.token);

      // 3) Load invite (tenant-scoped)
      const invite = await getInviteByTenantAndTokenHash(trx, {
        tenantId: tenant.id,
        tokenHash,
      });

      // 4) Enforce invite rules (pure policies)
      assertInviteExists(invite);
      assertInviteBelongsToTenant(invite, tenant.id);
      assertInviteIsPending(invite);
      assertInviteNotExpired(invite, now);

      // 5) Write: mark accepted (idempotency guard)
      const updated = await this.deps.inviteRepo.markAccepted({
        inviteId: invite.id,
        usedAt: now,
      });

      if (!updated) {
        throw InviteErrors.inviteNotPending({ inviteId: invite.id });
      }

      // 6) Audit (DB) — meaningful action
      await auditRepo.append({
        action: 'invite.accepted',
        tenantId: tenant.id,
        userId: null, // Brick 6 doesn’t authenticate a user yet
        membershipId: null, // Brick 6 doesn’t create/activate membership yet
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
        metadata: {
          inviteId: invite.id,
          email: invite.email,
          role: invite.role,
        },
      });

      this.deps.logger.info({
        msg: 'invites.accept.success',
        flow: 'invites.accept',
        requestId: params.requestId,
        tenantId: tenant.id,
        inviteId: invite.id,
        role: invite.role,
      });

      return {
        status: 'ACCEPTED',
        nextAction: 'SET_PASSWORD',
      };
    });
  }
}
