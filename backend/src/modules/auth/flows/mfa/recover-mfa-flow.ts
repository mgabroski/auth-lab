/**
 * backend/src/modules/auth/flows/mfa/recover-mfa-flow.ts
 *
 * WHY:
 * - Deep module for MFA recovery code verification (Brick 9c).
 * - Preserves rate limit + atomic recovery code usage + audit behavior exactly.
 */

import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import type { SessionStore } from '../../../../shared/session/session.store';
import type { RateLimiter } from '../../../../shared/security/rate-limit';

import type { KeyedHasher } from '../../../../shared/security/keyed-hasher';

import type { MfaRepo } from '../../dal/mfa.repo';
import { auditMfaRecoveryUsed } from '../../auth.audit';
import { MfaErrors } from './mfa-errors';

import { AUTH_RATE_LIMITS } from '../../auth.constants';

export async function recoverMfaFlow(params: {
  deps: {
    auditRepo: AuditRepo;
    sessionStore: SessionStore;
    rateLimiter: RateLimiter;
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
}): Promise<{ status: 'AUTHENTICATED'; nextAction: 'NONE' }> {
  const { deps, input } = params;

  if (input.mfaVerified) {
    throw MfaErrors.alreadyVerified();
  }

  await deps.rateLimiter.hitOrThrow({
    key: `mfa:recover:user:${input.userId}`,
    ...AUTH_RATE_LIMITS.mfaRecover.perUser,
  });

  const audit = new AuditWriter(deps.auditRepo, {
    requestId: input.requestId,
    ip: input.ip,
    userAgent: input.userAgent,
  }).withContext({
    tenantId: input.tenantId,
    userId: input.userId,
    membershipId: input.membershipId,
  });

  const codeHash = deps.mfaKeyedHasher.hash(input.recoveryCode);

  const used = await deps.mfaRepo.useRecoveryCodeAtomic({
    userId: input.userId,
    codeHash,
  });

  if (!used) {
    throw MfaErrors.invalidRecoveryCode();
  }

  await deps.sessionStore.updateSession(input.sessionId, { mfaVerified: true });
  await auditMfaRecoveryUsed(audit, { userId: input.userId });

  return { status: 'AUTHENTICATED', nextAction: 'NONE' };
}
