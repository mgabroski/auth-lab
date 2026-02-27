/**
 * backend/src/modules/auth/flows/password-reset/request-password-reset-flow.ts
 *
 * WHY:
 * - Deep module for the password-reset request use-case (Brick 8).
 * - Keeps AuthService thin; preserves anti-enumeration behavior.
 * - PR2: swaps fire-and-forget queue email to durable DB outbox row.
 *
 * RULES:
 * - Always returns void (controller returns 200 regardless).
 * - Silent rate-limit path is audited.
 * - User-not-found and SSO-only paths are silent but audited.
 * - No raw SQL here; use queries/repos.
 * - Outbox row is written in the SAME DB transaction as token changes.
 * - Outbox payload must never store raw email/token (tokenEnc + toEmailEnc only).
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';

import { generateSecureToken } from '../../../../shared/security/token';

import { auditPasswordResetRequested } from '../../auth.audit';

import { getUserByEmail } from '../../../users';
import { hasAuthIdentity } from '../../queries/auth.queries';
import type { AuthRepo } from '../../dal/auth.repo';

import { AUTH_RATE_LIMITS } from '../../auth.constants';

// Outbox (PR2)
import type { OutboxRepo } from '../../../../shared/outbox/outbox.repo';
import type { OutboxEncryption } from '../../../../shared/outbox/outbox-encryption';

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
    authRepo: AuthRepo;
    outboxRepo: OutboxRepo;
    outboxEncryption: OutboxEncryption;
  },
  params: RequestPasswordResetParams,
): Promise<void> {
  const email = params.email.toLowerCase();
  const emailKey = deps.tokenHasher.hash(email);

  const audit = new AuditWriter(deps.auditRepo, {
    requestId: params.requestId,
    ip: params.ip,
    userAgent: params.userAgent,
  });

  const withinLimit = await deps.rateLimiter.hitOrSkip({
    key: `forgot:email:${emailKey}`,
    ...AUTH_RATE_LIMITS.forgotPassword.perEmail,
  });

  if (!withinLimit) {
    await auditPasswordResetRequested(audit, { outcome: 'rate_limited' });
    return;
  }

  const user = await getUserByEmail(deps.db, email);
  if (!user) {
    await auditPasswordResetRequested(audit, { outcome: 'user_not_found' });
    return;
  }

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

  const rawToken = generateSecureToken();
  const tokenHash = deps.tokenHasher.hash(rawToken);
  const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);

  await deps.db.transaction().execute(async (trx) => {
    const authRepo = deps.authRepo.withDb(trx);

    // One-active-at-a-time rule
    await authRepo.invalidateActiveResetTokensForUser({ userId: user.id });

    await authRepo.insertPasswordResetToken({
      userId: user.id,
      tokenHash,
      expiresAt,
    });

    const payload = deps.outboxEncryption.encryptPayload({
      token: rawToken,
      toEmail: email,
      tenantKey: params.tenantKey ?? '',
      userId: user.id,
    });

    await deps.outboxRepo.enqueueWithinTx(trx, {
      type: 'password.reset',
      payload,
      idempotencyKey: `password-reset:${user.id}:${tokenHash}`,
    });
  });

  await auditPasswordResetRequested(audit.withContext({ userId: user.id }), {
    outcome: 'sent',
  });
}
