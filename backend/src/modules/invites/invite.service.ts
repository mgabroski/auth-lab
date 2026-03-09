/**
 * backend/src/modules/invites/invite.service.ts
 *
 * WHY:
 * - Thin facade. Delegates acceptInvite to execute-accept-invite-flow.ts.
 * - All orchestration, transactions, rate limiting, and audit live in the flow.
 *
 * RULES:
 * - No transactions here — flow owns the orchestration boundary (ER-18).
 * - No business logic — this method is a one-liner (ER-16).
 */

import type { DbExecutor } from '../../shared/db/db';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { Logger } from '../../shared/logger/logger';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import type { RateLimiter } from '../../shared/security/rate-limit';
import type { InviteRepo } from './dal/invite.repo';

import {
  executeAcceptInviteFlow,
  type AcceptInviteFlowParams,
  type AcceptInviteFlowResult,
} from './flows/execute-accept-invite-flow';

export type AcceptInviteParams = AcceptInviteFlowParams;
export type AcceptInviteResult = AcceptInviteFlowResult;

export class InviteService {
  constructor(
    private readonly deps: {
      db: DbExecutor;
      tokenHasher: TokenHasher;
      rateLimiter: RateLimiter;
      logger: Logger;
      inviteRepo: InviteRepo;
      auditRepo: AuditRepo;
    },
  ) {}

  async acceptInvite(params: AcceptInviteParams): Promise<AcceptInviteResult> {
    return executeAcceptInviteFlow(this.deps, params);
  }
}
