/**
 * backend/src/modules/control-plane/control-plane.module.ts
 *
 * WHY:
 * - Top-level module boundary for the Control Plane domain.
 * - Composes the currently shipped CP subdomains. Accounts is real in this repo; later CP areas stay deferred until explicitly added.
 * - DI (di.ts) only touches this file — never the subdomain modules directly.
 *
 * RULES:
 * - No infra construction here. All infra passed in from DI.
 * - One registerRoutes() delegates to each subdomain module.
 * - Adding a new CP subdomain means: create subdomain module, import here, wire.
 *
 * SHIPPED SUBDOMAIN MODULES:
 * - accounts: create/read/list, Step 2 saves, review/publish, status toggle, and producer-side handoff reads
 *
 * DEFERRED (later phases):
 * - additional CP domains beyond accounts
 */

import type { FastifyInstance } from 'fastify';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import type { DbExecutor } from '../../shared/db/db';
import type { Logger } from '../../shared/logger/logger';

import { createCpAccountsModule, type CpAccountsModule } from './accounts/cp-accounts.module';

export type ControlPlaneModule = ReturnType<typeof createControlPlaneModule>;

export function createControlPlaneModule(deps: {
  db: DbExecutor;
  logger: Logger;
  auditRepo: AuditRepo;
}) {
  const accounts: CpAccountsModule = createCpAccountsModule(deps);

  return {
    accounts,

    registerRoutes(app: FastifyInstance) {
      accounts.registerRoutes(app);
    },
  };
}
