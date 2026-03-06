/**
 * backend/src/modules/auth/flows/mfa/recover-mfa-flow.ts
 *
 * WHY:
 * - Deep module for MFA recovery code verification (Brick 9c).
 * - Preserves rate limit + atomic recovery code usage + audit behavior exactly.
 *
 * RULES:
 * - Recovery code consumption and success audit must commit together.
 * - Session rotation stays outside the DB transaction (Redis concern).
 */

import type { DbExecutor } from '../../../../shared/db/db';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import type { SessionStore } from '../../../../shared/session/session.store';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { TokenHasher } from '../../../../shared/security/token-hasher';

import type { KeyedHasher } from '../../../../shared/security/keyed-hasher';

import type { MfaRepo } from '../../dal/mfa.repo';
import { auditMfaRecoveryUsed } from '../../auth.audit';
import { MfaErrors } from './mfa-errors';
import { AppError } from '../../../../shared/http/errors';

import { AUTH_RATE_LIMITS } from '../../auth.constants';

export async function recoverMfaFlow(params: {
  deps: {
    db: DbExecutor;
    auditRepo: AuditRepo;
    sessionStore: SessionStore;
    rateLimiter: RateLimiter;
    tokenHasher: TokenHasher;
    mfaRepo: MfaRepo;
    mfaKeyedHasher: KeyedHasher;
  };
  input: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    mfaVerified: boolean;
    recoveryCode: string;
    requestId: string;
    ip: string;
    userAgent: string | null;
  };
}): Promise<{ status: 'AUTHENTICATED'; nextAction: 'NONE'; sessionId: string }> {
  const { deps, input } = params;

  if (input.mfaVerified) {
    throw MfaErrors.alreadyVerified();
  }

  const userKey = deps.tokenHasher.hash(input.userId);

  await deps.rateLimiter.hitOrThrow({
    key: `mfa:recover:user:${userKey}`,
    ...AUTH_RATE_LIMITS.mfaRecover.perUser,
  });

  const codeHash = deps.mfaKeyedHasher.hash(input.recoveryCode);

  await deps.db.transaction().execute(async (trx) => {
    const audit = new AuditWriter(deps.auditRepo.withDb(trx), {
      requestId: input.requestId,
      ip: input.ip,
      userAgent: input.userAgent,
    }).withContext({
      tenantId: input.tenantId,
      userId: input.userId,
      membershipId: input.membershipId,
    });

    const used = await deps.mfaRepo.withDb(trx).useRecoveryCodeAtomic({
      userId: input.userId,
      codeHash,
    });

    if (!used) {
      throw MfaErrors.invalidRecoveryCode();
    }

    await auditMfaRecoveryUsed(audit, { userId: input.userId });
  });

  const newSessionId = await deps.sessionStore.rotateSession(input.sessionId, {
    mfaVerified: true,
  });
  if (!newSessionId) {
    throw AppError.unauthorized('Session expired. Please sign in again.');
  }

  return { status: 'AUTHENTICATED', nextAction: 'NONE', sessionId: newSessionId };
}
