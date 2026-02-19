/**
 * backend/src/modules/auth/flows/password-reset/reset-password-flow.ts
 *
 * WHY:
 * - Deep module for consuming a password reset token and setting a new password (Brick 8).
 * - Keeps AuthService thin; preserves transactional behavior + audit pattern.
 *
 * RULES:
 * - Rate limit by IP (hard 429).
 * - Token is one-time use; invalid token always returns the same error.
 * - Must destroy ALL sessions for user after successful reset.
 * - Audit completed after transaction.
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { PasswordHasher } from '../../../../shared/security/password-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { SessionStore } from '../../../../shared/session/session.store';

import { auditPasswordResetCompleted } from '../../auth.audit';
import { AuthErrors } from '../../auth.errors';

import type { AuthRepo } from '../../dal/auth.repo';
import { getValidResetToken, hasAuthIdentity } from '../../queries/auth.queries';
import { getUserById } from '../../../users';

// ── Rate limit constant (kept identical) ────────────────────
const RESET_PASSWORD_LIMIT_PER_IP = { limit: 5, windowSeconds: 900 }; // hard 429

export type ResetPasswordParams = {
  tenantKey: string | null;
  token: string;
  newPassword: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export async function resetPasswordFlow(
  deps: {
    db: DbExecutor;
    tokenHasher: TokenHasher;
    passwordHasher: PasswordHasher;
    logger: Logger;
    rateLimiter: RateLimiter;
    auditRepo: AuditRepo;
    sessionStore: SessionStore;
    authRepo: AuthRepo;
  },
  params: ResetPasswordParams,
): Promise<void> {
  await deps.rateLimiter.hitOrThrow({
    key: `reset:ip:${params.ip}`,
    ...RESET_PASSWORD_LIMIT_PER_IP,
  });

  const tokenHash = deps.tokenHasher.hash(params.token);
  const resetToken = await getValidResetToken(deps.db, tokenHash);

  if (!resetToken) throw AuthErrors.resetTokenInvalid();

  const user = await getUserById(deps.db, resetToken.userId);
  if (!user) throw AuthErrors.resetTokenInvalid();

  const hasPassword = await hasAuthIdentity(deps.db, {
    userId: user.id,
    provider: 'password',
  });

  if (!hasPassword) throw AuthErrors.resetTokenInvalid();

  const newHash = await deps.passwordHasher.hash(params.newPassword);

  await deps.db.transaction().execute(async (trx) => {
    const authRepo = deps.authRepo.withDb(trx);

    await authRepo.updatePasswordHash({
      userId: user.id,
      newHash,
    });

    await authRepo.markResetTokenUsed({ tokenHash });
    await authRepo.invalidateActiveResetTokensForUser({ userId: user.id });
  });

  await deps.sessionStore.destroyAllForUser(user.id);

  const audit = new AuditWriter(deps.auditRepo, {
    requestId: params.requestId,
    ip: params.ip,
    userAgent: params.userAgent,
  }).withContext({ userId: user.id });

  await auditPasswordResetCompleted(audit, { userId: user.id });

  deps.logger.info({
    msg: 'auth.password_reset.completed',
    flow: 'auth.reset-password',
    requestId: params.requestId,
    userId: user.id,
  });
}
