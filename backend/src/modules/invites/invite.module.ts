/**
 * backend/src/modules/invites/invite.module.ts
 *
 * WHY:
 * - Encapsulates Invites module wiring.
 * - DI creates infra; module composes domain units.
 *
 * RULES:
 * - No infra creation here (DI passes deps in).
 * - No globals/singletons here.
 *
 * BRICK 12 UPDATE:
 * - Added rateLimiter deps (required by AdminInviteService).
 * - Wired AdminInviteController and registerAdminInviteRoutes.
 *
 * PR2 UPDATE:
 * - Admin invite emails are delivered via DB Outbox (durable).
 *
 * X8 UPDATE:
 * - Removed queue dep — AdminInviteService no longer accepts Queue.
 *   Email delivery is exclusively via the Outbox; the Queue import was dead code.
 */

import type { FastifyInstance } from 'fastify';
import type { DbExecutor } from '../../shared/db/db';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { RateLimiter } from '../../shared/security/rate-limit';
import type { Logger } from '../../shared/logger/logger';
import type { AuditRepo } from '../../shared/audit/audit.repo';

import type { OutboxRepo } from '../../shared/outbox/outbox.repo';
import type { OutboxEncryption } from '../../shared/outbox/outbox-encryption';

import { InviteController } from './invite.controller';
import { InviteService } from './invite.service';
import { registerInviteRoutes } from './invite.routes';
import { InviteRepo } from './dal/invite.repo';

import { AdminInviteService } from './admin/admin-invite.service';
import { AdminInviteController } from './admin/admin-invite.controller';
import { registerAdminInviteRoutes } from './admin/admin-invite.routes';

export type InviteModule = ReturnType<typeof createInviteModule>;

export function createInviteModule(deps: {
  db: DbExecutor;
  tokenHasher: TokenHasher;
  rateLimiter: RateLimiter;
  logger: Logger;
  auditRepo: AuditRepo;
  outboxRepo: OutboxRepo;
  outboxEncryption: OutboxEncryption;
}) {
  const inviteRepo = new InviteRepo(deps.db);

  const inviteService = new InviteService({
    db: deps.db,
    tokenHasher: deps.tokenHasher,
    rateLimiter: deps.rateLimiter,
    logger: deps.logger,
    inviteRepo,
    auditRepo: deps.auditRepo,
  });

  const adminInviteService = new AdminInviteService({
    db: deps.db,
    tokenHasher: deps.tokenHasher,
    rateLimiter: deps.rateLimiter,
    logger: deps.logger,
    inviteRepo,
    auditRepo: deps.auditRepo,
    outboxRepo: deps.outboxRepo,
    outboxEncryption: deps.outboxEncryption,
  });

  const controller = new InviteController(inviteService);
  const adminController = new AdminInviteController(adminInviteService);

  return {
    inviteService,
    registerRoutes(app: FastifyInstance) {
      registerInviteRoutes(app, controller);
      registerAdminInviteRoutes(app, adminController);
    },
  };
}
