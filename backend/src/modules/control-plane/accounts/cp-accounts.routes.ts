/**
 * backend/src/modules/control-plane/accounts/cp-accounts.routes.ts
 *
 * WHY:
 * - Declares the CP accounts HTTP route surface.
 * - Phase 4 adds backend-owned review composition and publish.
 */

import type { FastifyInstance } from 'fastify';
import type { CpAccountsController } from './cp-accounts.controller';

export function registerCpAccountsRoutes(
  app: FastifyInstance,
  controller: CpAccountsController,
): void {
  app.get('/cp/accounts', controller.listAccounts.bind(controller));
  app.get('/cp/accounts/:accountKey', controller.getAccount.bind(controller));
  app.get('/cp/accounts/:accountKey/review', controller.getReview.bind(controller));
  app.post('/cp/accounts', controller.createAccount.bind(controller));

  app.put('/cp/accounts/:accountKey/access', controller.saveAccess.bind(controller));
  app.put(
    '/cp/accounts/:accountKey/account-settings',
    controller.saveAccountSettings.bind(controller),
  );
  app.put('/cp/accounts/:accountKey/modules', controller.saveModuleSettings.bind(controller));
  app.put('/cp/accounts/:accountKey/modules/personal', controller.savePersonal.bind(controller));
  app.put('/cp/accounts/:accountKey/integrations', controller.saveIntegrations.bind(controller));

  app.post('/cp/accounts/:accountKey/publish', controller.publishAccount.bind(controller));
}
