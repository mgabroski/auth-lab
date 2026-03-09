/**
 * src/modules/auth/flows/logout/execute-logout-flow.ts
 *
 * WHY:
 * - logout owns session destruction and audit writing. Per ER-16/ER-18
 *   service mutation methods must be one-liners; orchestration belongs here.
 *
 * RULES:
 * - Session destroy before audit write — session ops are not transactional.
 * - Audit failure is caught and logged — logout must never be blocked by audit.
 * - No db.transaction() — session ops are Redis only, no DB writes required.
 */

import type { Logger } from '../../../../shared/logger/logger';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import type { SessionStore } from '../../../../shared/session/session.store';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import { auditLogout } from '../../auth.audit';

export type LogoutFlowParams = {
  sessionId: string;
  userId: string;
  tenantId: string;
  membershipId: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export async function executeLogoutFlow(
  deps: {
    sessionStore: SessionStore;
    auditRepo: AuditRepo;
    logger: Logger;
  },
  params: LogoutFlowParams,
): Promise<void> {
  await deps.sessionStore.destroy(params.sessionId);

  const audit = new AuditWriter(deps.auditRepo, {
    requestId: params.requestId,
    ip: params.ip,
    userAgent: params.userAgent,
  }).withContext({
    userId: params.userId,
    tenantId: params.tenantId,
    membershipId: params.membershipId,
  });

  try {
    await auditLogout(audit, { sessionId: params.sessionId });
  } catch (err) {
    deps.logger.error({
      msg: 'auth.logout.audit_failed',
      requestId: params.requestId,
      userId: params.userId,
      tenantId: params.tenantId,
      err,
    });
  }
}
