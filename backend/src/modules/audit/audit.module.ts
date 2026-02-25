/**
 * backend/src/modules/audit/audit.module.ts
 *
 * WHY:
 * - Encapsulates audit module wiring.
 * - DI passes deps in; module composes domain units.
 *
 * RULES:
 * - No infra creation here (DI passes deps in).
 * - No globals/singletons here.
 * - Exposes registerRoutes() so app/routes.ts can wire it in.
 */

import type { FastifyInstance } from 'fastify';
import type { DbExecutor } from '../../shared/db/db';

import { AdminAuditService } from './admin-audit.service';
import { AdminAuditController } from './admin-audit.controller';
import { registerAdminAuditRoutes } from './admin-audit.routes';

export type AuditModule = ReturnType<typeof createAuditModule>;

export function createAuditModule(deps: { db: DbExecutor }) {
  const adminAuditService = new AdminAuditService({ db: deps.db });
  const controller = new AdminAuditController(adminAuditService);

  return {
    adminAuditService,
    registerRoutes(app: FastifyInstance) {
      registerAdminAuditRoutes(app, controller);
    },
  };
}
