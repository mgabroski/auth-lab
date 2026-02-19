/**
 * backend/src/modules/auth/flows/login/execute-login-flow.ts
 *
 * WHY:
 * - "Flow" = deep module for one end-to-end use-case (Ousterhout).
 * - Keeps AuthService thin while isolating complex orchestration.
 * - Preserves the two-phase audit pattern:
 *   - success audit inside tx
 *   - failure audit outside tx (survives rollback)
 *
 * RULES:
 * - No HTTP concerns here (controller handles that).
 * - No raw SQL here (use queries/repos).
 * - Transactions are opened here (service delegates orchestration to the flow).
 *   This is still within "service/use-case orchestration layer" boundary.
 * - Keep behavior identical to the original AuthService.login().
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { PasswordHasher } from '../../../../shared/security/password-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { SessionStore } from '../../../../shared/session/session.store';

import { AuthErrors } from '../../auth.errors';
import type { AuthResult } from '../../auth.types';
import type { Tenant } from '../../../tenants/tenant.types';

import { auditLoginSuccess, auditLoginFailed } from '../../auth.audit';

import { resolveTenantForAuth } from '../../helpers/resolve-tenant-for-auth';
import { createAuthSession } from '../../helpers/create-auth-session';
import { buildAuthResult } from '../../helpers/build-auth-result';

import { getUserByEmail } from '../../../users';
import { getMembershipByTenantAndUser } from '../../../memberships';
import { getPasswordIdentityWithHash } from '../../queries/auth.queries';
import { hasVerifiedMfaSecret } from '../../helpers/has-verified-mfa-secret';

import { isMfaRequiredForLogin } from '../../policies/mfa-required.policy';
import { decideLoginNextAction } from '../../policies/login-next-action.policy';
import {
  getLoginMembershipGatingFailure,
  assertLoginMembershipAllowed,
} from '../../policies/login-membership-gating.policy';
import {
  getLoginPasswordIdentityFailure,
  assertLoginPasswordIdentityAllowed,
} from '../../policies/login-password-identity-gating.policy';

// ── Rate-limit constants (kept identical to AuthService) ─────
const LOGIN_LIMIT_PER_EMAIL = { limit: 5, windowSeconds: 900 };
const LOGIN_LIMIT_PER_IP = { limit: 20, windowSeconds: 900 };

// ── PII-safe helpers ─────────────────────────────────────────
function emailDomain(email: string): string {
  const at = email.lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1) : '';
}

// ── Types (copied from AuthService for now; later we can centralize) ───────
export type LoginParams = {
  tenantKey: string | null;
  email: string;
  password: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

type LoginFailureContext = {
  tenantId: string;
  userId?: string;
  membershipId?: string;
  email: string;
  reason: string;
  error: Error;
};

type LoginTxResult = {
  user: { id: string; email: string; name: string | null };
  membership: { id: string; role: 'ADMIN' | 'MEMBER'; status: 'ACTIVE' | 'INVITED' | 'SUSPENDED' };
  tenant: Tenant;
};

export async function executeLoginFlow(
  deps: {
    db: DbExecutor;
    tokenHasher: TokenHasher;
    passwordHasher: PasswordHasher;
    logger: Logger;
    rateLimiter: RateLimiter;
    auditRepo: AuditRepo;
    sessionStore: SessionStore;
  },
  params: LoginParams,
): Promise<{ result: AuthResult; sessionId: string }> {
  const email = params.email.toLowerCase();
  const emailKey = deps.tokenHasher.hash(email);

  deps.logger.info({
    msg: 'auth.login.start',
    flow: 'auth.login',
    requestId: params.requestId,
    tenantKey: params.tenantKey,
    emailDomain: emailDomain(email),
    emailKey,
  });

  await deps.rateLimiter.hitOrThrow({
    key: `login:email:${emailKey}`,
    ...LOGIN_LIMIT_PER_EMAIL,
  });
  await deps.rateLimiter.hitOrThrow({
    key: `login:ip:${params.ip}`,
    ...LOGIN_LIMIT_PER_IP,
  });

  let failureCtx: LoginFailureContext | null = null;
  let txResult: LoginTxResult | null = null;

  try {
    txResult = await deps.db.transaction().execute(async (trx): Promise<LoginTxResult> => {
      const audit = new AuditWriter(deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      });

      const tenant = await resolveTenantForAuth(trx, params.tenantKey);

      const user = await getUserByEmail(trx, email);
      if (!user) {
        failureCtx = {
          tenantId: tenant.id,
          email,
          reason: 'user_not_found',
          error: AuthErrors.invalidCredentials(),
        };
        throw failureCtx.error;
      }

      const passwordResult = await getPasswordIdentityWithHash(trx, user.id);

      const pwFailure = getLoginPasswordIdentityFailure(passwordResult);
      if (pwFailure) {
        failureCtx = {
          tenantId: tenant.id,
          userId: user.id,
          email,
          reason: pwFailure.reason,
          error: pwFailure.error,
        };
        throw failureCtx.error;
      }
      assertLoginPasswordIdentityAllowed(passwordResult);

      const passwordValid = await deps.passwordHasher.verify(
        params.password,
        passwordResult.passwordHash,
      );
      if (!passwordValid) {
        failureCtx = {
          tenantId: tenant.id,
          userId: user.id,
          email,
          reason: 'wrong_password',
          error: AuthErrors.invalidCredentials(),
        };
        throw failureCtx.error;
      }

      const membership = await getMembershipByTenantAndUser(trx, {
        tenantId: tenant.id,
        userId: user.id,
      });

      const gatingFailure = getLoginMembershipGatingFailure(membership);
      if (gatingFailure) {
        failureCtx = {
          tenantId: tenant.id,
          userId: user.id,
          membershipId: membership?.id,
          email,
          reason: gatingFailure.reason,
          error: gatingFailure.error,
        };
        throw failureCtx.error;
      }
      assertLoginMembershipAllowed(membership);

      const fullAudit = audit
        .withContext({ tenantId: tenant.id })
        .withContext({ userId: user.id, membershipId: membership.id });

      await auditLoginSuccess(fullAudit, {
        userId: user.id,
        email: user.email,
        membershipId: membership.id,
        role: membership.role,
      });

      return {
        user: { id: user.id, email: user.email, name: user.name ?? null },
        membership: { id: membership.id, role: membership.role, status: membership.status },
        tenant,
      };
    });
  } catch (err) {
    if (failureCtx) {
      const ctx = failureCtx as LoginFailureContext;

      const failAudit = new AuditWriter(deps.auditRepo, {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext({
        tenantId: ctx.tenantId,
        userId: ctx.userId ?? null,
        membershipId: ctx.membershipId ?? null,
      });

      await auditLoginFailed(failAudit, {
        email: ctx.email,
        reason: ctx.reason,
      });
    }

    throw err;
  }

  if (!txResult) {
    throw new Error('auth.login: transaction completed without result');
  }

  const { user, membership, tenant } = txResult;

  const mfaIsRequired = isMfaRequiredForLogin({
    role: membership.role,
    tenantMemberMfaRequired: tenant.memberMfaRequired,
  });

  const hasVerifiedMfaSecretValue = mfaIsRequired
    ? await hasVerifiedMfaSecret(deps.db, user.id)
    : false;

  const nextAction = decideLoginNextAction({
    role: membership.role,
    memberMfaRequired: tenant.memberMfaRequired,
    hasVerifiedMfaSecret: hasVerifiedMfaSecretValue,
  });

  const { sessionId } = await createAuthSession({
    sessionStore: deps.sessionStore,
    userId: user.id,
    tenantId: tenant.id,
    tenantKey: tenant.key,
    membershipId: membership.id,
    role: membership.role,
    tenant,
    hasVerifiedMfaSecret: hasVerifiedMfaSecretValue,
    now: new Date(),
  });

  deps.logger.info({
    msg: 'auth.login.success',
    flow: 'auth.login',
    requestId: params.requestId,
    tenantId: tenant.id,
    userId: user.id,
    membershipId: membership.id,
  });

  return {
    sessionId,
    result: buildAuthResult({ nextAction, user, membership }),
  };
}
