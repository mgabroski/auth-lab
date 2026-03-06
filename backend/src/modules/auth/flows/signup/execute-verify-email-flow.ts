/**
 * backend/src/modules/auth/flows/signup/execute-verify-email-flow.ts
 *
 * WHY:
 * - Brick 11: consumes an email verification token and flips users.email_verified.
 * - Session-required: the user must be authenticated (they just signed up).
 *
 * RULES (from locked decisions):
 * - POST /auth/verify-email does NOT create a new session.
 * - It DOES upgrade the existing server-side session (Redis) so that
 *   session.emailVerified becomes true after successful verification.
 *   This removes the need for logout/login after verification.
 * - Idempotency: if the token is valid AND belongs to the session user AND the
 *   user is already verified, return success without error. This prevents a
 *   token oracle.
 * - Token and email_verified update are committed in a single transaction
 *   (locked Decision: atomic consumption).
 * - Audit inside tx.
 * - Rate limit: 10/IP/15min (Decision 5) — prevents brute-forcing tokens.
 *
 * SECURITY:
 * - We verify the token belongs to the session's userId BEFORE checking
 *   email_verified. This prevents the token from being used as an oracle to
 *   determine whether ANY email exists in the system.
 * - Rate limit fires BEFORE any DB work (same rule as every other flow).
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { SessionStore } from '../../../../shared/session/session.store';

import type { EmailVerificationRepo } from '../../dal/email-verification.repo';
import { getValidVerificationToken } from '../../queries/email-verification.queries';
import { getUserById } from '../../../users';

import { AuthErrors } from '../../auth.errors';
import { auditEmailVerified } from '../../auth.audit';
import { AUTH_RATE_LIMITS } from '../../auth.constants';

export type VerifyEmailParams = {
  sessionId: string;
  sessionUserId: string;
  tenantId: string;
  membershipId: string;
  token: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export async function executeVerifyEmailFlow(
  deps: {
    db: DbExecutor;
    tokenHasher: TokenHasher;
    logger: Logger;
    rateLimiter: RateLimiter;
    auditRepo: AuditRepo;
    emailVerificationRepo: EmailVerificationRepo;
    sessionStore: SessionStore;
  },
  params: VerifyEmailParams,
): Promise<{ status: 'VERIFIED' }> {
  const ipKey = deps.tokenHasher.hash(params.ip);

  await deps.rateLimiter.hitOrThrow({
    key: `verify-email:ip:${ipKey}`,
    ...AUTH_RATE_LIMITS.verifyEmail.perIp,
  });

  const tokenHash = deps.tokenHasher.hash(params.token);

  deps.logger.info({
    msg: 'auth.verify-email.start',
    flow: 'auth.verify-email',
    requestId: params.requestId,
    userId: params.sessionUserId,
  });

  await deps.db.transaction().execute(async (trx) => {
    const emailVerificationRepo = deps.emailVerificationRepo.withDb(trx);

    const baseAudit = new AuditWriter(deps.auditRepo.withDb(trx), {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    });

    const token = await getValidVerificationToken(trx, tokenHash);

    if (!token) {
      throw AuthErrors.verificationTokenInvalid();
    }

    if (token.userId !== params.sessionUserId) {
      throw AuthErrors.verificationTokenInvalid();
    }

    const user = await getUserById(trx, params.sessionUserId);
    if (!user) {
      throw AuthErrors.verificationTokenInvalid();
    }

    if (user.emailVerified) {
      await emailVerificationRepo.markVerificationTokenUsed({ tokenHash });
      return;
    }

    await emailVerificationRepo.markVerificationTokenUsed({ tokenHash });
    await emailVerificationRepo.markUserEmailVerified({ userId: params.sessionUserId });

    await emailVerificationRepo.invalidateActiveVerificationTokensForUser({
      userId: params.sessionUserId,
    });

    const fullAudit = baseAudit.withContext({
      tenantId: params.tenantId,
      userId: params.sessionUserId,
      membershipId: params.membershipId,
    });

    await auditEmailVerified(fullAudit, { userId: params.sessionUserId });
  });

  try {
    await deps.sessionStore.updateSession(params.sessionId, { emailVerified: true });
  } catch (err) {
    deps.logger.error({
      msg: 'auth.verify-email.session-upgrade-failed',
      flow: 'auth.verify-email',
      requestId: params.requestId,
      userId: params.sessionUserId,
      error: (err as Error).message,
    });
  }

  deps.logger.info({
    msg: 'auth.verify-email.success',
    flow: 'auth.verify-email',
    requestId: params.requestId,
    userId: params.sessionUserId,
  });

  return { status: 'VERIFIED' };
}
