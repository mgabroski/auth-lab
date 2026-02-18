/**
 * backend/src/modules/auth/flows/register/execute-register-flow.ts
 *
 * WHY:
 * - "Flow" = deep module for one end-to-end use-case (Ousterhout).
 * - Keeps AuthService thin while isolating orchestration complexity.
 *
 * RULES:
 * - No HTTP concerns here.
 * - No raw SQL here (use queries/repos/helpers).
 * - Transactions are opened here (still within service/use-case orchestration layer).
 * - Keep behavior identical to the original AuthService.register().
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { PasswordHasher } from '../../../../shared/security/password-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { SessionStore } from '../../../../shared/session/session.store';
import type { Queue } from '../../../../shared/messaging/queue';

import type { UserRepo } from '../../../users/dal/user.repo';
import type { MembershipRepo } from '../../../memberships/dal/membership.repo';
import type { AuthRepo } from '../../dal/auth.repo';

import type { AuthResult } from '../../auth.types';

import { resolveTenantForAuth } from '../../helpers/resolve-tenant-for-auth';
import { validateInviteForRegister } from '../../helpers/validate-invite-for-register';
import { ensurePasswordIdentity } from '../../helpers/ensure-password-identity';
import { provisionUserToTenant } from '../../../_shared/use-cases/provision-user-to-tenant.usecase';
import { writeRegisterAudits } from '../../helpers/write-register-audits';
import { createAuthSession } from '../../helpers/create-auth-session';
import { buildAuthResult } from '../../helpers/build-auth-result';

// ── Rate-limit constants (kept identical to AuthService) ─────
const REGISTER_LIMIT_PER_EMAIL = { limit: 5, windowSeconds: 900 };
const REGISTER_LIMIT_PER_IP = { limit: 20, windowSeconds: 900 };

// ── PII-safe helpers ─────────────────────────────────────────
function emailDomain(email: string): string {
  const at = email.lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1) : '';
}

// Keep params local to the flow to avoid cross-file type churn.
// This matches the AuthService.RegisterParams shape.
export type RegisterParams = {
  tenantKey: string | null;
  email: string;
  password: string;
  name: string;
  inviteToken: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export async function executeRegisterFlow(
  deps: {
    db: DbExecutor;
    tokenHasher: TokenHasher;
    passwordHasher: PasswordHasher;
    logger: Logger;
    rateLimiter: RateLimiter;
    auditRepo: AuditRepo;
    sessionStore: SessionStore;
    queue: Queue;
    userRepo: UserRepo;
    membershipRepo: MembershipRepo;
    authRepo: AuthRepo;
  },
  params: RegisterParams,
): Promise<{ result: AuthResult; sessionId: string }> {
  const email = params.email.toLowerCase();
  const emailKey = deps.tokenHasher.hash(email);
  const now = new Date();

  deps.logger.info({
    msg: 'auth.register.start',
    flow: 'auth.register',
    requestId: params.requestId,
    tenantKey: params.tenantKey,
    emailDomain: emailDomain(email),
    emailKey,
  });

  await deps.rateLimiter.hitOrThrow({
    key: `register:email:${emailKey}`,
    ...REGISTER_LIMIT_PER_EMAIL,
  });

  await deps.rateLimiter.hitOrThrow({
    key: `register:ip:${params.ip}`,
    ...REGISTER_LIMIT_PER_IP,
  });

  const { user, membership, tenant } = await deps.db.transaction().execute(async (trx) => {
    const userRepo = deps.userRepo.withDb(trx);
    const membershipRepo = deps.membershipRepo.withDb(trx);
    const authRepo = deps.authRepo.withDb(trx);

    const baseAudit = new AuditWriter(deps.auditRepo.withDb(trx), {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    });

    const tenant = await resolveTenantForAuth(trx, params.tenantKey);

    const invite = await validateInviteForRegister({
      trx,
      tokenHasher: deps.tokenHasher,
      tenantId: tenant.id,
      inviteToken: params.inviteToken,
      email,
    });

    const provisionResult = await provisionUserToTenant({
      trx,
      userRepo,
      membershipRepo,
      email,
      name: params.name,
      tenantId: tenant.id,
      role: invite.role,
      now,
    });

    await ensurePasswordIdentity({
      trx,
      authRepo,
      passwordHasher: deps.passwordHasher,
      userId: provisionResult.user.id,
      rawPassword: params.password,
    });

    const fullAudit = baseAudit.withContext({
      tenantId: tenant.id,
      userId: provisionResult.user.id,
      membershipId: provisionResult.membership.id,
    });

    await writeRegisterAudits(fullAudit, provisionResult);

    return { ...provisionResult, tenant };
  });

  // New user will never have MFA configured yet, but keep it explicit.
  const hasVerifiedMfaSecret = false;

  const { sessionId, nextAction } = await createAuthSession({
    sessionStore: deps.sessionStore,
    userId: user.id,
    tenantId: tenant.id,
    tenantKey: tenant.key,
    membershipId: membership.id,
    role: membership.role,
    tenant,
    hasVerifiedMfaSecret,
    now,
  });

  deps.logger.info({
    msg: 'auth.register.success',
    flow: 'auth.register',
    requestId: params.requestId,
    tenantId: tenant.id,
    userId: user.id,
    membershipId: membership.id,
    role: membership.role,
  });

  return {
    sessionId,
    result: buildAuthResult({ nextAction, user, membership }),
  };
}
