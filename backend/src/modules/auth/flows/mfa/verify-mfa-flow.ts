/**
 * backend/src/modules/auth/flows/mfa/verify-mfa-flow.ts
 *
 * WHY:
 * - Deep module for verifying MFA during login (Brick 9b).
 * - Preserves rate limit + audit behavior exactly.
 */

import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import type { DbExecutor } from '../../../../shared/db/db';
import type { SessionStore } from '../../../../shared/session/session.store';
import type { RateLimiter } from '../../../../shared/security/rate-limit';

import type { TotpService } from '../../../../shared/security/totp';
import type { EncryptionService } from '../../../../shared/security/encryption';

import { getMfaSecretForUser } from '../../queries/mfa.queries';
import { auditMfaVerifyFailed, auditMfaVerifySuccess } from '../../auth.audit';
import { MfaErrors } from './mfa-errors';

// Brick 9 (MFA) rate limits (global per-user)
const MFA_VERIFY_LIMIT_PER_USER = { limit: 5, windowSeconds: 900 }; // hard 429

export async function verifyMfaFlow(params: {
  deps: {
    db: DbExecutor;
    auditRepo: AuditRepo;
    sessionStore: SessionStore;
    rateLimiter: RateLimiter;
    totpService: TotpService;
    encryptionService: EncryptionService;
  };
  input: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    mfaVerified: boolean;
    code: string;
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
    key: `mfa:verify:user:${input.userId}`,
    ...MFA_VERIFY_LIMIT_PER_USER,
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

  const secretRow = await getMfaSecretForUser(deps.db, input.userId);
  if (!secretRow || !secretRow.isVerified) {
    throw MfaErrors.mfaNotConfigured();
  }

  const plaintextSecret = deps.encryptionService.decrypt(secretRow.secretEncrypted);
  const ok = deps.totpService.verify(plaintextSecret, input.code);

  if (!ok) {
    await auditMfaVerifyFailed(audit, { userId: input.userId });
    throw MfaErrors.invalidCode();
  }

  await deps.sessionStore.updateSession(input.sessionId, { mfaVerified: true });
  await auditMfaVerifySuccess(audit, { userId: input.userId });

  return { status: 'AUTHENTICATED', nextAction: 'NONE' };
}
