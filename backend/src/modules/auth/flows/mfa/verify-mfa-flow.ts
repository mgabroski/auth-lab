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
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { Cache } from '../../../../shared/cache/cache';
import type { Logger } from '../../../../shared/logger/logger';

import type { TotpService } from '../../../../shared/security/totp';
import type { EncryptionService } from '../../../../shared/security/encryption';

import { getMfaSecretForUser } from '../../queries/mfa.queries';
import { auditMfaVerifyFailed, auditMfaVerifySuccess } from '../../auth.audit';
import { MfaErrors } from './mfa-errors';
import { AppError } from '../../../../shared/http/errors';

import { AUTH_RATE_LIMITS } from '../../auth.constants';

export async function verifyMfaFlow(params: {
  deps: {
    db: DbExecutor;
    auditRepo: AuditRepo;
    sessionStore: SessionStore;
    rateLimiter: RateLimiter;
    tokenHasher: TokenHasher; // Stage 4
    cache: Cache;
    logger: Logger;
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
}): Promise<{ status: 'AUTHENTICATED'; nextAction: 'NONE'; sessionId: string }> {
  const { deps, input } = params;

  if (input.mfaVerified) {
    throw MfaErrors.alreadyVerified();
  }

  // Stage 4: hash stable identifiers in Redis key material.
  const userKey = deps.tokenHasher.hash(input.userId);

  await deps.rateLimiter.hitOrThrow({
    key: `mfa:verify:user:${userKey}`,
    ...AUTH_RATE_LIMITS.mfaVerify.perUser,
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

  // Replay protection: the same TOTP code must not be accepted twice.
  // Fail-open on cache errors: a Redis blip must not lock out all MFA users.
  const usedCodeKey = `totp:used:${userKey}:${input.code}`;

  let alreadyUsed: string | null = null;
  try {
    alreadyUsed = await deps.cache.get(usedCodeKey);
  } catch (err) {
    deps.logger.warn('mfa.replay_cache_read_error', {
      flow: 'mfa.verify',
      userId: input.userId,
      error: (err as Error).message,
    });
  }

  if (alreadyUsed) {
    await auditMfaVerifyFailed(audit, { userId: input.userId });
    throw MfaErrors.invalidCode();
  }

  // Mark as used for 2 full TOTP periods (120s covers ±1 window + realistic clock drift).
  // Fail-open on cache WRITE error — the rate limiter bounds worst-case replay exposure.
  try {
    await deps.cache.set(usedCodeKey, '1', { ttlSeconds: 120 });
  } catch (err) {
    deps.logger.warn('mfa.replay_cache_write_error', {
      flow: 'mfa.verify',
      userId: input.userId,
      error: (err as Error).message,
    });
  }

  const newSessionId = await deps.sessionStore.rotateSession(input.sessionId, {
    mfaVerified: true,
  });
  if (!newSessionId) throw AppError.unauthorized('Session expired. Please sign in again.');

  await auditMfaVerifySuccess(audit, { userId: input.userId });

  return { status: 'AUTHENTICATED', nextAction: 'NONE', sessionId: newSessionId };
}
