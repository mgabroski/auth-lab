/**
 * backend/src/modules/auth/flows/signup/execute-verify-email-flow.ts
 *
 * WHY:
 * - Brick 11: consumes an email verification token and flips users.email_verified.
 * - Session-required: the user must be authenticated (they just signed up).
 *
 * RULES (from locked decisions):
 * - POST /auth/verify-email does NOT create a new session and does NOT modify
 *   the existing session. It only flips email_verified and consumes the token.
 *   The user continues with their current session.
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

import type { EmailVerificationRepo } from '../../dal/email-verification.repo';
import { getValidVerificationToken } from '../../queries/email-verification.queries';
import { getUserById } from '../../../users';

import { AuthErrors } from '../../auth.errors';
import { auditEmailVerified } from '../../auth.audit';
import { AUTH_RATE_LIMITS } from '../../auth.constants';

export type VerifyEmailParams = {
  /** From session (controller calls requireSession first). */
  sessionUserId: string;
  tenantId: string;
  membershipId: string;
  /** Raw token from request body. */
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
  },
  params: VerifyEmailParams,
): Promise<{ status: 'VERIFIED' }> {
  // ── Rate limit (before any DB work — Decision 5) ────────────────────────

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

    // ── 1. Load valid token ────────────────────────────────────────────────
    const token = await getValidVerificationToken(trx, tokenHash);

    if (!token) {
      throw AuthErrors.verificationTokenInvalid();
    }

    // ── 2. Verify token belongs to the session user ────────────────────────
    // This check is non-negotiable: prevents one user from consuming another
    // user's token. Always enforce even if user.emailVerified is already true.
    if (token.userId !== params.sessionUserId) {
      // Return the same error as invalid token — no oracle.
      throw AuthErrors.verificationTokenInvalid();
    }

    // ── 3. Load current user to check idempotency ──────────────────────────
    const user = await getUserById(trx, params.sessionUserId);
    if (!user) {
      // Should never happen (session guarantees user exists), but be defensive.
      throw AuthErrors.verificationTokenInvalid();
    }

    // ── 4. Idempotency guard ───────────────────────────────────────────────
    // If user is already verified and the token is valid + belongs to them,
    // treat it as success — consume the token to prevent re-use but don't error.
    if (user.emailVerified) {
      // Consume token so it can't be replayed.
      await emailVerificationRepo.markVerificationTokenUsed({ tokenHash });
      // No audit written for no-op re-verification.
      return;
    }

    // ── 5. Atomic: consume token + flip email_verified ─────────────────────
    await emailVerificationRepo.markVerificationTokenUsed({ tokenHash });
    await emailVerificationRepo.markUserEmailVerified({ userId: params.sessionUserId });

    // Invalidate any other active tokens for this user (cleanup).
    await emailVerificationRepo.invalidateActiveVerificationTokensForUser({
      userId: params.sessionUserId,
    });

    // ── 6. Audit (inside tx) ──────────────────────────────────────────────
    const fullAudit = baseAudit.withContext({
      tenantId: params.tenantId,
      userId: params.sessionUserId,
      membershipId: params.membershipId,
    });

    await auditEmailVerified(fullAudit, { userId: params.sessionUserId });
  });

  deps.logger.info({
    msg: 'auth.verify-email.success',
    flow: 'auth.verify-email',
    requestId: params.requestId,
    userId: params.sessionUserId,
  });

  return { status: 'VERIFIED' };
}
