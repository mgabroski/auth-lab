/**
 * backend/src/modules/control-plane/accounts/cp-accounts.routes.ts
 *
 * WHY:
 * - Declares the CP accounts HTTP route surface.
 * - Phase 3 adds real Step 2 group save endpoints.
 */

import type { FastifyInstance } from 'fastify';
import type { CpAccountsController } from './cp-accounts.controller';

export function registerCpAccountsRoutes(
  app: FastifyInstance,
  controller: CpAccountsController,
): void {
  app.get('/cp/accounts', controller.listAccounts.bind(controller));
  app.get('/cp/accounts/:accountKey', controller.getAccount.bind(controller));
  app.post('/cp/accounts', controller.createAccount.bind(controller));

  app.put('/cp/accounts/:accountKey/access', controller.saveAccess.bind(controller));
  app.put(
    '/cp/accounts/:accountKey/account-settings',
    controller.saveAccountSettings.bind(controller),
  );
  app.put('/cp/accounts/:accountKey/modules', controller.saveModuleSettings.bind(controller));
  app.put('/cp/accounts/:accountKey/modules/personal', controller.savePersonal.bind(controller));
  app.put('/cp/accounts/:accountKey/integrations', controller.saveIntegrations.bind(controller));
}
