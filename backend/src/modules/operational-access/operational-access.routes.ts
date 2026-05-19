/**
 * backend/src/modules/operational-access/operational-access.routes.ts
 *
 * WHY:
 * - Declares the Operational Access Step 3 configuration foundation routes.
 *
 * RULES:
 * - Routes configure future access data only.
 * - No resolver, Special Access, Oversight, Temporary Coverage, or runtime visibility routes.
 */

import type { FastifyInstance } from 'fastify';
import type { OperationalAccessController } from './operational-access.controller';

export function registerOperationalAccessRoutes(
  app: FastifyInstance,
  controller: OperationalAccessController,
): void {
  app.get('/operational-access/catalog', controller.getCatalog.bind(controller));
  app.get('/operational-access/groups', controller.listGroups.bind(controller));
  app.get('/operational-access/people', controller.listPeople.bind(controller));
  app.get('/operational-access/groups/:groupId', controller.getGroup.bind(controller));
  app.put(
    '/operational-access/groups/:groupId/grants',
    controller.saveGroupGrants.bind(controller),
  );
  app.put(
    '/operational-access/groups/:groupId/responsible-for',
    controller.saveResponsibleFor.bind(controller),
  );
}
