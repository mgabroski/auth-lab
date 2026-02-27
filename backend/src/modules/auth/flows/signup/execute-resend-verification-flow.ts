/**
 * backend/src/modules/auth/flows/signup/execute-resend-verification-flow.ts
 *
 * WHY:
 * - Brick 11: user may not receive the first verification email; this provides
 *   a self-service retry path.
 * - PR2: swaps fire-and-forget queue email to durable DB outbox row.
 *
 * RULES (from locked decisions):
 * - Requires authentication; uses sessionUserId (not body email) to prevent enumeration.
 * - Always returns 200 — never reveals rate-limit status or verified state.
 * - If user.emailVerified is already true: return 200 without generating tokens (no-op).
 * - Rate limit is SILENT (hitOrSkip): 3 per email per hour. Over limit → 200, no email sent.
 * - Invalidates prior active tokens before inserting a new one (one-active-at-a-time rule).
 * - No session modification.
 * - Outbox row is written in the SAME DB transaction as token insert.
 * - Outbox payload must never store raw email/token (tokenEnc + toEmailEnc only).
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';

import type { EmailVerificationRepo } from '../../dal/email-verification.repo';
import { getUserById } from '../../../users';

import { generateSecureToken } from '../../../../shared/security/token';
import { AUTH_RATE_LIMITS, EMAIL_VERIFICATION_TTL_SECONDS } from '../../auth.constants';

// Outbox (PR2)
import type { OutboxRepo } from '../../../../shared/outbox/outbox.repo';
import type { OutboxEncryption } from '../../../../shared/outbox/outbox-encryption';

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
    emailVerificationRepo: EmailVerificationRepo;
    outboxRepo: OutboxRepo;
    outboxEncryption: OutboxEncryption;
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
  const user = await getUserById(deps.db, params.sessionUserId);
  if (!user) {
    // Session is valid but user doesn't exist — shouldn't happen in practice.
    // Return silently to avoid oracle.
    return;
  }

  // ── 2. Silent rate limit (3 per email per hour) ────────────────────────────
  const emailKey = deps.tokenHasher.hash(user.email);
  const allowed = await deps.rateLimiter.hitOrSkip({
    key: `resend-verification:email:${emailKey}`,
    ...AUTH_RATE_LIMITS.resendVerification.perEmail,
  });

  if (!allowed) {
    deps.logger.info({
      msg: 'auth.resend-verification.rate-limited',
      flow: 'auth.resend-verification',
      requestId: params.requestId,
      userId: params.sessionUserId,
    });
    return;
  }

  // ── 3. Idempotency: already verified → no-op ──────────────────────────────
  if (user.emailVerified) {
    deps.logger.info({
      msg: 'auth.resend-verification.already-verified',
      flow: 'auth.resend-verification',
      requestId: params.requestId,
      userId: params.sessionUserId,
    });
    return;
  }

  // ── 4. Generate new token + invalidate old ones + Outbox enqueue ───────────
  const now = new Date();

  await deps.db.transaction().execute(async (trx) => {
    const emailVerificationRepo = deps.emailVerificationRepo.withDb(trx);

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

    const payload = deps.outboxEncryption.encryptPayload({
      token: rawToken,
      toEmail: user.email,
      tenantKey: params.tenantKey,
      userId: user.id,
    });

    await deps.outboxRepo.enqueueWithinTx(trx, {
      type: 'email.verify',
      payload,
      idempotencyKey: `email-verify-resend:${user.id}:${tokenHash}`,
    });
  });

  deps.logger.info({
    msg: 'auth.resend-verification.sent',
    flow: 'auth.resend-verification',
    requestId: params.requestId,
    userId: params.sessionUserId,
  });
}
