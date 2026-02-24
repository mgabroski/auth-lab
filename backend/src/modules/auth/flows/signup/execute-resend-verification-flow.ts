/**
 * backend/src/modules/auth/flows/signup/execute-resend-verification-flow.ts
 *
 * WHY:
 * - Brick 11: user may not receive the first verification email; this provides
 *   a self-service retry path.
 *
 * RULES (from locked decisions and Correction #2):
 * - Always returns 200 — never reveals token existence or email_verified status
 *   to prevent enumeration.
 * - If user.emailVerified is already true: return 200 without generating tokens.
 *   (Correction #2: idempotency — resend for verified user is a no-op.)
 * - Rate limit is SILENT (hitOrSkip, same pattern as forgot-password):
 *   3 per email per hour. Over limit → 200 but no email sent.
 * - Invalidates prior active tokens before inserting a new one
 *   (one-active-at-a-time rule).
 * - No session modification (Correction #1).
 *
 * SECURITY:
 * - Uses sessionUserId (not email from request body) to avoid email enumeration.
 *   The user must be authenticated; we trust the session for userId.
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { Queue } from '../../../../shared/messaging/queue';

import type { EmailVerificationRepo } from '../../dal/email-verification.repo';
import { getUserById } from '../../../users';

import { generateSecureToken } from '../../../../shared/security/token';
import { AUTH_RATE_LIMITS, EMAIL_VERIFICATION_TTL_SECONDS } from '../../auth.constants';

export type ResendVerificationParams = {
  /** From session — never trust email from request body for this operation. */
  sessionUserId: string;
  tenantKey: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export async function executeResendVerificationFlow(
  deps: {
    db: DbExecutor;
    tokenHasher: TokenHasher;
    logger: Logger;
    rateLimiter: RateLimiter;
    queue: Queue;
    emailVerificationRepo: EmailVerificationRepo;
  },
  params: ResendVerificationParams,
): Promise<void> {
  deps.logger.info({
    msg: 'auth.resend-verification.start',
    flow: 'auth.resend-verification',
    requestId: params.requestId,
    userId: params.sessionUserId,
  });

  // ── 1. Load user to get email for rate-limit key ───────────────────────────
  // We do this before the rate-limit check so we can key by email hash.
  const user = await getUserById(deps.db, params.sessionUserId);
  if (!user) {
    // Session is valid but user doesn't exist — shouldn't happen in practice.
    // Return silently to avoid oracle.
    return;
  }

  // ── 2. Silent rate limit (3 per email per hour) ────────────────────────────
  // hitOrSkip: does NOT throw. Returns false when over limit.
  // Same pattern as forgot-password.
  const emailKey = deps.tokenHasher.hash(user.email);
  const allowed = await deps.rateLimiter.hitOrSkip({
    key: `resend-verification:email:${emailKey}`,
    ...AUTH_RATE_LIMITS.resendVerification.perEmail,
  });

  if (!allowed) {
    // Over limit — silent, identical response to success.
    deps.logger.info({
      msg: 'auth.resend-verification.rate-limited',
      flow: 'auth.resend-verification',
      requestId: params.requestId,
      userId: params.sessionUserId,
    });
    return;
  }

  // ── 3. Idempotency: already verified → no-op (Correction #2) ──────────────
  if (user.emailVerified) {
    deps.logger.info({
      msg: 'auth.resend-verification.already-verified',
      flow: 'auth.resend-verification',
      requestId: params.requestId,
      userId: params.sessionUserId,
    });
    return;
  }

  // ── 4. Generate new token, invalidate old ones ─────────────────────────────
  const now = new Date();

  await deps.db.transaction().execute(async (trx) => {
    const emailVerificationRepo = deps.emailVerificationRepo.withDb(trx);

    // Invalidate active tokens first (one-active-at-a-time rule).
    await emailVerificationRepo.invalidateActiveVerificationTokensForUser({
      userId: params.sessionUserId,
    });

    const rawToken = generateSecureToken();
    const tokenHash = deps.tokenHasher.hash(rawToken);
    const expiresAt = new Date(now.getTime() + EMAIL_VERIFICATION_TTL_SECONDS * 1000);

    await emailVerificationRepo.insertVerificationToken({
      userId: params.sessionUserId,
      tokenHash,
      expiresAt,
    });

    // Enqueue outside tx (but still inside the function — fire-and-forget).
    // Raw token travels to the queue only, never stored.
    await deps.queue.enqueue({
      type: 'auth.signup-verification-email',
      userId: user.id,
      email: user.email,
      verificationToken: rawToken,
      tenantKey: params.tenantKey,
    });
  });

  deps.logger.info({
    msg: 'auth.resend-verification.sent',
    flow: 'auth.resend-verification',
    requestId: params.requestId,
    userId: params.sessionUserId,
  });
}
