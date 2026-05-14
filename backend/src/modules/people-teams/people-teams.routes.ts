/**
 * backend/src/modules/people-teams/people-teams.routes.ts
 *
 * WHY:
 * - Declares the People & Teams backend foundation routes.
 *
 * RULES:
 * - Routes remain limited to group lifecycle and group membership management.
 * - No Operational Access grants, Person Exceptions, Managed People,
 *   or resolver routes.
 */

import type { FastifyInstance } from 'fastify';
import type { PeopleTeamsController } from './people-teams.controller';

export function registerPeopleTeamsRoutes(
  app: FastifyInstance,
  controller: PeopleTeamsController,
): void {
  app.get('/people-teams/groups', controller.listGroups.bind(controller));
  app.post('/people-teams/groups', controller.createGroup.bind(controller));
  app.get('/people-teams/groups/:groupId', controller.getGroup.bind(controller));
  app.get('/people-teams/groups/:groupId/members', controller.listGroupMembers.bind(controller));
  app.post('/people-teams/groups/:groupId/members', controller.addGroupMember.bind(controller));
  app.delete(
    '/people-teams/groups/:groupId/members/:membershipId',
    controller.removeGroupMember.bind(controller),
  );
  app.put('/people-teams/groups/:groupId', controller.updateGroup.bind(controller));
  app.post('/people-teams/groups/:groupId/archive', controller.archiveGroup.bind(controller));
  app.get('/people-teams/people', controller.listPeople.bind(controller));
}
