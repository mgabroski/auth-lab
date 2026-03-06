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
 *
 * X2 — Rate limit added:
 * - verify-setup was the only MFA endpoint without a rate limit.
 * - An attacker holding a setup-phase session could brute-force 6-digit TOTP
 *   codes (10^6 attempts) without restriction.
 * - Rate limit key: mfa:setup-verify:user:<hashed-userId>
 * - Reuses AUTH_RATE_LIMITS.mfaVerify.perUser (5 attempts / 15 min) — same
 *   policy as the login-phase MFA verify endpoint.
 * - hitOrThrow fires BEFORE any DB work, consistent with the house rule:
 *   "rate limit early — before DB work — on every endpoint that accepts credentials."
 */

import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import type { DbExecutor } from '../../../../shared/db/db';
import type { SessionStore } from '../../../../shared/session/session.store';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
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
import { AUTH_RATE_LIMITS } from '../../auth.constants';

export async function verifyMfaSetupFlow(params: {
  deps: {
    db: DbExecutor;
    auditRepo: AuditRepo;
    sessionStore: SessionStore;
    rateLimiter: RateLimiter;
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

  const userKey = deps.tokenHasher.hash(input.userId);

  await deps.rateLimiter.hitOrThrow({
    key: `mfa:setup-verify:user:${userKey}`,
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
  if (!secretRow || secretRow.isVerified) {
    throw MfaErrors.noSetupInProgress();
  }

  const plaintextSecret = deps.encryptionService.decrypt(secretRow.secretEncrypted);
  const ok = deps.totpService.verify(plaintextSecret, input.code);

  if (!ok) {
    await auditMfaVerifyFailed(audit, { userId: input.userId });
    throw MfaErrors.invalidCode();
  }

  const usedCodeKey = `totp:used:${userKey}:${input.code}`;

  let claimed = true;
  try {
    claimed = await deps.cache.setIfAbsent(usedCodeKey, '1', { ttlSeconds: 120 });
  } catch (err) {
    deps.logger.warn('mfa.replay_cache_write_error', {
      flow: 'mfa.verify_setup',
      userId: input.userId,
      error: (err as Error).message,
    });
  }

  if (!claimed) {
    await auditMfaVerifyFailed(audit, { userId: input.userId });
    throw MfaErrors.invalidCode();
  }

  await deps.mfaRepo.verifyMfaSecret({ userId: input.userId });

  const newSessionId = await deps.sessionStore.rotateSession(input.sessionId, {
    mfaVerified: true,
  });
  if (!newSessionId) throw AppError.unauthorized('Session expired. Please sign in again.');

  await auditMfaSetupCompleted(audit, { userId: input.userId });

  return { status: 'AUTHENTICATED', nextAction: 'NONE', sessionId: newSessionId };
}
