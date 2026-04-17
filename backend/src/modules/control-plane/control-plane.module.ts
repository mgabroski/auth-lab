/**
 * backend/src/modules/control-plane/control-plane.module.ts
 *
 * WHY:
 * - Top-level module boundary for the Control Plane domain.
 * - Composes all CP subdomains (accounts now; settings, tasks, benefits later).
 * - DI (di.ts) only touches this file — never the subdomain modules directly.
 *
 * RULES:
 * - No infra construction here. All infra passed in from DI.
 * - One registerRoutes() delegates to each subdomain module.
 * - Adding a new CP subdomain means: create subdomain module, import here, wire.
 *
 * SUBDOMAIN MODULES (Phase 2):
 * - accounts: GET/POST /cp/accounts, GET /cp/accounts/:accountKey
 *
 * DEFERRED (later phases):
 * - settings group save modules (access, account-settings, modules, integrations)
 * - publish module
 * - status management
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
