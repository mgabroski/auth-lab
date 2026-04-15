/**
 * backend/src/modules/control-plane/accounts/cp-accounts.module.ts
 *
 * WHY:
 * - Encapsulates wiring for the CP accounts subdomain.
 * - Composes repo, service, controller, and route registration.
 * - Called by control-plane.module.ts, not by di.ts directly.
 *
 * RULES:
 * - No infra construction here (DI passes db and logger in).
 * - No globals/singletons.
 * - Exposes registerRoutes for the parent module to call.
 */

import type { FastifyInstance } from 'fastify';
import type { DbExecutor } from '../../../shared/db/db';
import type { Logger } from '../../../shared/logger/logger';

import { CpAccountsRepo } from './dal/cp-accounts.repo';
import { CpAccountsService } from './cp-accounts.service';
import { CpAccountsController } from './cp-accounts.controller';
import { registerCpAccountsRoutes } from './cp-accounts.routes';

export type CpAccountsModule = ReturnType<typeof createCpAccountsModule>;

export function createCpAccountsModule(deps: { db: DbExecutor; logger: Logger }) {
  const cpAccountsRepo = new CpAccountsRepo(deps.db);

  const cpAccountsService = new CpAccountsService({
    db: deps.db,
    logger: deps.logger,
    cpAccountsRepo,
  });

  const cpAccountsController = new CpAccountsController(cpAccountsService);

  return {
    cpAccountsService,

    registerRoutes(app: FastifyInstance) {
      registerCpAccountsRoutes(app, cpAccountsController);
    },
  };
}
