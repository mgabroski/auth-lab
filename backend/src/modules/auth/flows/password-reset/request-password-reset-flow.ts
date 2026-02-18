/**
 * backend/src/modules/auth/flows/password-reset/request-password-reset-flow.ts
 *
 * WHY:
 * - Deep module for the password-reset request use-case (Brick 8).
 * - Keeps AuthService thin; preserves anti-enumeration behavior.
 *
 * RULES:
 * - Always returns void (controller returns 200 regardless).
 * - Silent rate-limit path is audited.
 * - User-not-found and SSO-only paths are silent but audited.
 * - No raw SQL here; use queries/repos.
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { Queue } from '../../../../shared/messaging/queue';

import { generateSecureToken } from '../../../../shared/security/token';

import { auditPasswordResetRequested } from '../../auth.audit';

import { getUserByEmail } from '../../../users/queries/user.queries';
import { hasAuthIdentity } from '../../queries/auth.queries';
import type { AuthRepo } from '../../dal/auth.repo';

// ── Rate limit constant (kept identical) ────────────────────
const FORGOT_PASSWORD_LIMIT_PER_EMAIL = { limit: 3, windowSeconds: 3600 }; // silent

// Password reset token TTL: 1 hour (kept identical)
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000;

export type RequestPasswordResetParams = {
  tenantKey: string | null;
  email: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export async function requestPasswordResetFlow(
  deps: {
    db: DbExecutor;
    tokenHasher: TokenHasher;
    logger: Logger;
    rateLimiter: RateLimiter;
    auditRepo: AuditRepo;
    queue: Queue;
    authRepo: AuthRepo;
  },
  params: RequestPasswordResetParams,
): Promise<void> {
  const email = params.email.toLowerCase();
  const emailKey = deps.tokenHasher.hash(email);

  // Base audit writer — no tenant/user context yet (we may not find them)
  const audit = new AuditWriter(deps.auditRepo, {
    requestId: params.requestId,
    ip: params.ip,
    userAgent: params.userAgent,
  });

  // ── 1. Silent rate limit ─────────────────────────────────
  const withinLimit = await deps.rateLimiter.hitOrSkip({
    key: `forgot:email:${emailKey}`,
    ...FORGOT_PASSWORD_LIMIT_PER_EMAIL,
  });

  if (!withinLimit) {
    await auditPasswordResetRequested(audit, { outcome: 'rate_limited' });
    return;
  }

  // ── 2. Find user ─────────────────────────────────────────
  const user = await getUserByEmail(deps.db, email);
  if (!user) {
    await auditPasswordResetRequested(audit, { outcome: 'user_not_found' });
    return;
  }

  // ── 3. Check for password identity ──────────────────────
  const hasPassword = await hasAuthIdentity(deps.db, {
    userId: user.id,
    provider: 'password',
  });

  if (!hasPassword) {
    await auditPasswordResetRequested(audit.withContext({ userId: user.id }), {
      outcome: 'sso_only',
    });
    return;
  }

  // ── 4. Invalidate any existing active tokens ─────────────
  await deps.authRepo.invalidateActiveResetTokensForUser({ userId: user.id });

  // ── 5. Generate and store new token ─────────────────────
  const rawToken = generateSecureToken();
  const tokenHash = deps.tokenHasher.hash(rawToken);
  const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);

  await deps.authRepo.insertPasswordResetToken({
    userId: user.id,
    tokenHash,
    expiresAt,
  });

  // ── 6. Enqueue reset email ───────────────────────────────
  await deps.queue.enqueue({
    type: 'auth.reset-password-email',
    userId: user.id,
    email,
    resetToken: rawToken,
    tenantKey: params.tenantKey ?? '',
  });

  // ── 7. Audit ─────────────────────────────────────────────
  await auditPasswordResetRequested(audit.withContext({ userId: user.id }), {
    outcome: 'sent',
  });
}
