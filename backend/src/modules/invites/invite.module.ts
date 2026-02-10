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
 */

import type { FastifyInstance } from 'fastify';
import type { DbExecutor } from '../../shared/db/db';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { Logger } from '../../shared/logger/logger';

import type { AuditRepo } from '../../shared/audit/audit.repo';

import { InviteController } from './invite.controller';
import { InviteService } from './invite.service';
import { registerInviteRoutes } from './invite.routes';
import { InviteRepo } from './dal/invite.repo';

export type InviteModule = ReturnType<typeof createInviteModule>;

export function createInviteModule(deps: {
  db: DbExecutor;
  tokenHasher: TokenHasher;
  logger: Logger;
  auditRepo: AuditRepo;
}) {
  const inviteRepo = new InviteRepo(deps.db);

  const inviteService = new InviteService({
    db: deps.db,
    tokenHasher: deps.tokenHasher,
    logger: deps.logger,
    inviteRepo,
    auditRepo: deps.auditRepo,
  });

  const controller = new InviteController(inviteService);

  return {
    inviteService,
    registerRoutes(app: FastifyInstance) {
      registerInviteRoutes(app, controller);
    },
  };
}
