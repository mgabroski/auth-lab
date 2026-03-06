/**
 * backend/src/modules/invites/invite.service.ts
 *
 * WHY:
 * - Accepts an invite token for the current tenant.
 * - Writes acceptance + audit in one transaction.
 *
 * RULES:
 * - Tenant is resolved from request subdomain and REQUIRED.
 * - Invite lookup is tenant-scoped.
 * - Token is hashed before lookup.
 * - No queue side-effects here.
 * - Keep AppError usage out of DAL/queries/policies.
 */

import type { DbExecutor } from '../../shared/db/db';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { Logger } from '../../shared/logger/logger';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import { AuditWriter } from '../../shared/audit/audit.writer';

import {
  getTenantByKey,
  assertTenantKeyPresent,
  assertTenantExists,
  assertTenantIsActive,
} from '../tenants';
import { getUserByEmail } from '../users';
import { getMfaSecretForUser } from '../auth/queries/mfa.queries';
import { getInviteByTenantAndTokenHash } from './queries/invite.queries';

import {
  assertInviteBelongsToTenant,
  assertInviteExists,
  assertInviteIsPending,
  assertInviteNotExpired,
} from './policies/invite.policy';
import { InviteErrors } from './invite.errors';
import { auditInviteAccepted } from './invite.audit';

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
      const inviteRepo = this.deps.inviteRepo.withDb(trx);

      const audit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      });

      assertTenantKeyPresent(params.tenantKey);

      const tenant = await getTenantByKey(trx, params.tenantKey);
      assertTenantExists(tenant, params.tenantKey);
      assertTenantIsActive(tenant);

      const tenantAudit = audit.withContext({ tenantId: tenant.id });

      const tokenHash = this.deps.tokenHasher.hash(params.token);

      const invite = await getInviteByTenantAndTokenHash(trx, {
        tenantId: tenant.id,
        tokenHash,
      });

      assertInviteExists(invite);
      assertInviteBelongsToTenant(invite, tenant.id);
      assertInviteIsPending(invite);
      assertInviteNotExpired(invite, now);

      const updated = await inviteRepo.markAccepted({
        inviteId: invite.id,
        usedAt: now,
      });

      if (!updated) {
        throw InviteErrors.inviteNotPending({ inviteId: invite.id });
      }

      const existingUser = await getUserByEmail(trx, invite.email);

      let nextAction: AcceptInviteResult['nextAction'] = 'SET_PASSWORD';
      if (existingUser) {
        nextAction = 'SIGN_IN';

        if (invite.role === 'ADMIN') {
          const mfaSecret = await getMfaSecretForUser(trx, existingUser.id);
          if (!mfaSecret?.isVerified) {
            nextAction = 'MFA_SETUP_REQUIRED';
          }
        }
      }

      await auditInviteAccepted(tenantAudit, invite);

      this.deps.logger.info({
        msg: 'invites.accept.success',
        flow: 'invites.accept',
        requestId: params.requestId,
        tenantId: tenant.id,
        inviteId: invite.id,
        role: invite.role,
        nextAction,
      });

      return {
        status: 'ACCEPTED',
        nextAction,
      };
    });
  }
}
