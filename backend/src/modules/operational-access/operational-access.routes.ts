/**
 * backend/src/modules/operational-access/operational-access.routes.ts
 *
 * WHY:
 * - Declares Operational Access configuration routes and the OA-owned runtime proof surface for `personal_cards.view`.
 *
 * RULES:
 * - Admin configuration routes remain admin-only in the controller.
 * - Runtime proof routes delegate effective access to the backend resolver.
 * - No frontend code computes effective access.
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

  app.get(
    '/operational-access/advanced-coverage',
    controller.listAdvancedCoverage.bind(controller),
  );
  app.put(
    '/operational-access/advanced-coverage/oversight',
    controller.saveOversight.bind(controller),
  );
  app.put(
    '/operational-access/advanced-coverage/temporary-coverage',
    controller.saveTemporaryCoverage.bind(controller),
  );
  app.put(
    '/operational-access/advanced-coverage/special-access',
    controller.saveSpecialAccess.bind(controller),
  );

  app.get('/operational-access/runtime/people', controller.listRuntimePeople.bind(controller));
  app.get(
    '/operational-access/runtime/people/:membershipId',
    controller.getRuntimePerson.bind(controller),
  );
}
