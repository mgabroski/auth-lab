/**
 * backend/src/modules/auth/flows/mfa/verify-mfa-setup-flow.ts
 *
 * WHY:
 * - Deep module for verifying MFA setup (Brick 9a).
 * - Preserves behavior exactly.
 *
 * RULES:
 * - Requires an unverified secret in DB
 * - Verifies TOTP code
 * - Marks secret verified + marks session mfaVerified=true
 * - Audits: verify failed (on wrong code), setup completed (on success)
 */

import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import type { DbExecutor } from '../../../../shared/db/db';
import type { SessionStore } from '../../../../shared/session/session.store';
import type { Cache } from '../../../../shared/cache/cache';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { Logger } from '../../../../shared/logger/logger';

import type { TotpService } from '../../../../shared/security/totp';
import type { EncryptionService } from '../../../../shared/security/encryption';

import type { MfaRepo } from '../../dal/mfa.repo';
import { getMfaSecretForUser } from '../../queries/mfa.queries';
import { auditMfaVerifyFailed, auditMfaSetupCompleted } from '../../auth.audit';
import { MfaErrors } from './mfa-errors';
import { AppError } from '../../../../shared/http/errors';

export async function verifyMfaSetupFlow(params: {
  deps: {
    db: DbExecutor;
    auditRepo: AuditRepo;
    sessionStore: SessionStore;
    mfaRepo: MfaRepo;
    cache: Cache;
    tokenHasher: TokenHasher;
    logger: Logger;
    totpService: TotpService;
    encryptionService: EncryptionService;
  };
  input: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    code: string;
    requestId: string;
    ip: string;
    userAgent: string | null;
  };
}): Promise<{ status: 'AUTHENTICATED'; nextAction: 'NONE'; sessionId: string }> {
  const { deps, input } = params;

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
  if (!secretRow || secretRow.isVerified) {
    throw MfaErrors.noSetupInProgress();
  }

  const plaintextSecret = deps.encryptionService.decrypt(secretRow.secretEncrypted);
  const ok = deps.totpService.verify(plaintextSecret, input.code);

  if (!ok) {
    await auditMfaVerifyFailed(audit, { userId: input.userId });
    throw MfaErrors.invalidCode();
  }

  // Replay protection: the same TOTP code must not be accepted twice.
  // Fail-open on cache errors: a Redis blip must not lock out all MFA users.
  const userKey = deps.tokenHasher.hash(input.userId);
  const usedCodeKey = `totp:used:${userKey}:${input.code}`;

  let alreadyUsed: string | null = null;
  try {
    alreadyUsed = await deps.cache.get(usedCodeKey);
  } catch (err) {
    deps.logger.warn('mfa.replay_cache_read_error', {
      flow: 'mfa.verify_setup',
      userId: input.userId,
      error: (err as Error).message,
    });
  }

  if (alreadyUsed) {
    await auditMfaVerifyFailed(audit, { userId: input.userId });
    throw MfaErrors.invalidCode();
  }

  // Mark as used for 2 full TOTP periods (120s covers ±1 window + realistic clock drift).
  // Fail-open on cache WRITE error — rate limiting bounds worst-case replay exposure.
  try {
    await deps.cache.set(usedCodeKey, '1', { ttlSeconds: 120 });
  } catch (err) {
    deps.logger.warn('mfa.replay_cache_write_error', {
      flow: 'mfa.verify_setup',
      userId: input.userId,
      error: (err as Error).message,
    });
  }

  await deps.mfaRepo.verifyMfaSecret({ userId: input.userId });

  const newSessionId = await deps.sessionStore.rotateSession(input.sessionId, {
    mfaVerified: true,
  });
  if (!newSessionId) throw AppError.unauthorized('Session expired. Please sign in again.');

  await auditMfaSetupCompleted(audit, { userId: input.userId });

  return { status: 'AUTHENTICATED', nextAction: 'NONE', sessionId: newSessionId };
}
