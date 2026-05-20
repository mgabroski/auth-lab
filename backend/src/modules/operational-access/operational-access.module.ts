/**
 * backend/src/modules/operational-access/operational-access.module.ts
 *
 * WHY:
 * - Top-level module boundary for Operational Access configuration plus the
 *   `personal_cards.view` resolver proof surface.
 * - Composes product-defined grant configuration, base/advanced coverage,
 *   Special Access, and backend-owned effective access decisions.
 */

import type { FastifyInstance } from 'fastify';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import type { DbExecutor } from '../../shared/db/db';
import { OperationalAccessRepo } from './dal/operational-access.repo';
import { OperationalAccessController } from './operational-access.controller';
import { registerOperationalAccessRoutes } from './operational-access.routes';
import { OperationalAccessService } from './operational-access.service';

export type OperationalAccessModule = ReturnType<typeof createOperationalAccessModule>;

export function createOperationalAccessModule(deps: { db: DbExecutor; auditRepo: AuditRepo }) {
  const repo = new OperationalAccessRepo(deps.db);
  const service = new OperationalAccessService({ db: deps.db, auditRepo: deps.auditRepo, repo });
  const controller = new OperationalAccessController(service);

  return {
    repo,
    service,
    registerRoutes(app: FastifyInstance) {
      registerOperationalAccessRoutes(app, controller);
    },
  };
}
