/**
 * backend/src/modules/control-plane/accounts/cp-accounts.routes.ts
 *
 * WHY:
 * - Declares the CP accounts HTTP route surface.
 * - Keeps routing separate from controller logic.
 *
 * ROUTE PREFIX:
 * - All CP backend routes are prefixed with /cp/ (per CP prerequisite roadmap §7.3).
 * - This file owns the /cp/accounts surface only.
 *
 * PHASE 2 SURFACE:
 * - GET  /cp/accounts            — list all CP accounts
 * - GET  /cp/accounts/:accountKey — get single CP account by key
 * - POST /cp/accounts            — create a new Draft CP account
 *
 * DEFERRED (to later phases):
 * - PUT  /cp/accounts/:accountKey/access
 * - PUT  /cp/accounts/:accountKey/account-settings
 * - PUT  /cp/accounts/:accountKey/modules
 * - PUT  /cp/accounts/:accountKey/modules/personal
 * - PUT  /cp/accounts/:accountKey/integrations
 * - POST /cp/accounts/:accountKey/publish
 * - PATCH /cp/accounts/:accountKey/status
 *
 * AUTH:
 * - Dev-only no-auth is acceptable for CP in this phase.
 * - CP authentication will be added in a later phase.
 *
 * RULES:
 * - No business logic here.
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
}
