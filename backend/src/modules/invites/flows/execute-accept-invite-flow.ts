/**
 * src/modules/invites/flows/execute-accept-invite-flow.ts
 *
 * WHY:
 * - acceptInvite is a mutation that owns a transaction, rate limit, and two-phase
 *   audit. Per ER-18 these responsibilities belong in a flow, not a service.
 *
 * RULES:
 * - Rate limit before db.transaction() (ER-19).
 * - Success audit inside transaction (ER-38).
 * - Failure audit in catch using bare auditRepo — not .withDb(trx) — so it
 *   survives rollback (ER-39).
 * - No business logic in InviteService after this extraction — it is a one-liner.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { TokenHasher } from '../../../shared/security/token-hasher';
import type { Logger } from '../../../shared/logger/logger';
import type { AuditRepo } from '../../../shared/audit/audit.repo';
import type { RateLimiter } from '../../../shared/security/rate-limit';
import { AuditWriter } from '../../../shared/audit/audit.writer';

import {
  getTenantByKey,
  assertTenantKeyPresent,
  assertTenantExists,
  assertTenantIsActive,
} from '../../tenants';
import { getUserByEmail } from '../../users';
import { getMfaSecretForUser } from '../../auth';
import { getInviteByTenantAndTokenHash } from '../queries/invite.queries';

import {
  assertInviteBelongsToTenant,
  assertInviteIsPending,
  assertInviteNotExpired,
} from '../policies/invite.policy';
import { InviteErrors } from '../invite.errors';
import { auditInviteAccepted, auditInviteAcceptFailed } from '../invite.audit';
import { INVITE_ACCEPT_RATE_LIMITS } from '../invite.constants';

import type { InviteRepo } from '../dal/invite.repo';

export type AcceptInviteFlowParams = {
  tenantKey: string | null;
  token: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export type AcceptInviteFlowResult = {
  status: 'ACCEPTED';
  nextAction: 'SET_PASSWORD' | 'SIGN_IN' | 'MFA_SETUP_REQUIRED';
};

type FailureCtx = {
  tenantId: string | null;
  userId: string | null;
  reason: string;
};

export async function executeAcceptInviteFlow(
  deps: {
    db: DbExecutor;
    tokenHasher: TokenHasher;
    rateLimiter: RateLimiter;
    logger: Logger;
    inviteRepo: InviteRepo;
    auditRepo: AuditRepo;
  },
  params: AcceptInviteFlowParams,
): Promise<AcceptInviteFlowResult> {
  const now = new Date();
  const ipKey = deps.tokenHasher.hash(params.ip);

  // ── Rate limit — before any DB work (ER-19) ──────────────────────────
  await deps.rateLimiter.hitOrThrow({
    key: `invite-accept:ip:${ipKey}`,
    ...INVITE_ACCEPT_RATE_LIMITS.acceptInvite.perIp,
  });

  deps.logger.info({
    msg: 'invites.accept.start',
    flow: 'invites.accept',
    requestId: params.requestId,
    tenantKey: params.tenantKey,
    ipKey, // hashed — never log raw IP (ER-40)
  });

  let failureCtx: FailureCtx | null = null;
  let txResult: AcceptInviteFlowResult | null = null;

  try {
    txResult = await deps.db.transaction().execute(async (trx) => {
      const inviteRepo = deps.inviteRepo.withDb(trx);

      // ── Success audit writer — bound to trx (ER-38) ──────────────────
      const audit = new AuditWriter(deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      });

      assertTenantKeyPresent(params.tenantKey);

      const tenant = await getTenantByKey(trx, params.tenantKey);
      assertTenantExists(tenant, params.tenantKey);
      assertTenantIsActive(tenant);

      const tenantAudit = audit.withContext({ tenantId: tenant.id });

      const tokenHash = deps.tokenHasher.hash(params.token);
      const invite = await getInviteByTenantAndTokenHash(trx, {
        tenantId: tenant.id,
        tokenHash,
      });

      if (!invite) {
        failureCtx = { tenantId: tenant.id, userId: null, reason: 'invite_not_found' };
        throw InviteErrors.inviteNotFound();
      }

      assertInviteBelongsToTenant(invite, tenant.id);

      try {
        assertInviteIsPending(invite);
      } catch (err) {
        failureCtx = { tenantId: tenant.id, userId: null, reason: 'invite_not_pending' };
        throw err;
      }

      try {
        assertInviteNotExpired(invite, now);
      } catch (err) {
        failureCtx = { tenantId: tenant.id, userId: null, reason: 'invite_expired' };
        throw err;
      }

      const updated = await inviteRepo.markAccepted({
        inviteId: invite.id,
        usedAt: now,
      });

      if (!updated) {
        failureCtx = { tenantId: tenant.id, userId: null, reason: 'invite_concurrent_accept' };
        throw InviteErrors.inviteNotPending({ inviteId: invite.id });
      }

      const existingUser = await getUserByEmail(trx, invite.email);

      let nextAction: AcceptInviteFlowResult['nextAction'] = 'SET_PASSWORD';
      if (existingUser) {
        nextAction = 'SIGN_IN';
        if (invite.role === 'ADMIN') {
          const mfaSecret = await getMfaSecretForUser(trx, existingUser.id);
          if (!mfaSecret?.isVerified) {
            nextAction = 'MFA_SETUP_REQUIRED';
          }
        }
      }

      const finalAudit = existingUser
        ? tenantAudit.withContext({ userId: existingUser.id })
        : tenantAudit;

      // ── Success audit — inside tx (ER-38) ────────────────────────────
      await auditInviteAccepted(finalAudit, invite);

      return { status: 'ACCEPTED' as const, nextAction };
    });
  } catch (err) {
    // ── Failure audit — bare auditRepo, outside tx (ER-39) ───────────
    if (failureCtx) {
      const ctx = failureCtx as FailureCtx;
      const failAudit = new AuditWriter(deps.auditRepo, {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({
        tenantId: ctx.tenantId,
        userId: ctx.userId,
        membershipId: null,
      });
      await auditInviteAcceptFailed(failAudit, { reason: ctx.reason });
    }
    throw err;
  }

  if (!txResult) {
    throw new Error('invites.accept: transaction completed without result');
  }

  deps.logger.info({
    msg: 'invites.accept.success',
    flow: 'invites.accept',
    requestId: params.requestId,
    nextAction: txResult.nextAction,
  });

  return txResult;
}
