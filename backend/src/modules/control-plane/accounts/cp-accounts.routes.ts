/**
 * backend/src/modules/control-plane/accounts/cp-accounts.routes.ts
 *
 * WHY:
 * - Declares the shipped CP accounts HTTP route surface.
 * - Keeps create/read/list, Step 2 saves, review/publish, and status toggle registered in one explicit place.
 * - Applies the current CP host-boundary pre-handler to every route so tenant
 *   hosts cannot reach the no-auth CP backend surface.
 *
 * RULES:
 * - Keep this file routing-only. No validation or business logic here.
 * - Route generics must stay explicit when route options are introduced so
 *   controller request contracts remain strictly typed.
 */

import type { FastifyInstance } from 'fastify';

import type { AppConfig } from '../../../app/config';
import type { CpAccountsController } from './cp-accounts.controller';
import { buildCpBoundaryPreHandler } from './cp-accounts.boundary';

type AccountKeyRoute = {
  Params: {
    accountKey: string;
  };
};

export function registerCpAccountsRoutes(
  app: FastifyInstance,
  controller: CpAccountsController,
  config: AppConfig,
): void {
  const preHandler = buildCpBoundaryPreHandler(config);

  app.get('/cp/accounts', { preHandler }, controller.listAccounts.bind(controller));
  app.post('/cp/accounts', { preHandler }, controller.createAccount.bind(controller));

  app.get<AccountKeyRoute>(
    '/cp/accounts/:accountKey',
    { preHandler },
    controller.getAccount.bind(controller),
  );

  app.get<AccountKeyRoute>(
    '/cp/accounts/:accountKey/review',
    { preHandler },
    controller.getReview.bind(controller),
  );

  app.put<AccountKeyRoute>(
    '/cp/accounts/:accountKey/access',
    { preHandler },
    controller.saveAccess.bind(controller),
  );

  app.put<AccountKeyRoute>(
    '/cp/accounts/:accountKey/account-settings',
    { preHandler },
    controller.saveAccountSettings.bind(controller),
  );

  app.put<AccountKeyRoute>(
    '/cp/accounts/:accountKey/modules',
    { preHandler },
    controller.saveModuleSettings.bind(controller),
  );

  app.put<AccountKeyRoute>(
    '/cp/accounts/:accountKey/modules/personal',
    { preHandler },
    controller.savePersonal.bind(controller),
  );

  app.put<AccountKeyRoute>(
    '/cp/accounts/:accountKey/integrations',
    { preHandler },
    controller.saveIntegrations.bind(controller),
  );

  app.post<AccountKeyRoute>(
    '/cp/accounts/:accountKey/publish',
    { preHandler },
    controller.publishAccount.bind(controller),
  );

  app.patch<AccountKeyRoute>(
    '/cp/accounts/:accountKey/status',
    { preHandler },
    controller.updateStatus.bind(controller),
  );
}
