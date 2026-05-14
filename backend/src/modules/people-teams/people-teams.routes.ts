/**
 * backend/src/modules/people-teams/people-teams.routes.ts
 *
 * WHY:
 * - Declares the People & Teams backend foundation routes.
 *
 * RULES:
 * - This foundation is read-only: group list and active tenant people selector only.
 * - No Operational Access grants, Person Exceptions, Managed People, or resolver routes.
 */

import type { FastifyInstance } from 'fastify';
import type { PeopleTeamsController } from './people-teams.controller';

export function registerPeopleTeamsRoutes(
  app: FastifyInstance,
  controller: PeopleTeamsController,
): void {
  app.get('/people-teams/groups', controller.listGroups.bind(controller));
  app.get('/people-teams/people', controller.listPeople.bind(controller));
}
