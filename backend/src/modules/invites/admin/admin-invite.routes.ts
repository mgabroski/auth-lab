/**
 * backend/src/modules/invites/admin/admin-invite.routes.ts
 *
 * WHY:
 * - Declares admin invite endpoints.
 * - Keeps routing separate from controller logic.
 *
 * RULES:
 * - No business logic here.
 * - All four admin endpoints require ADMIN role + MFA — enforced in controller,
 *   not in route definitions, keeping guards visible at the controller layer.
 *
 * PR1: POST /admin/invites.
 * PR2: GET /admin/invites, POST /admin/invites/:inviteId/resend, DELETE /admin/invites/:inviteId.
 */

import type { FastifyInstance } from 'fastify';
import type { AdminInviteController } from './admin-invite.controller';

export function registerAdminInviteRoutes(
  app: FastifyInstance,
  controller: AdminInviteController,
): void {
  app.post('/admin/invites', controller.createInvite.bind(controller));
  app.get('/admin/invites', controller.listInvites.bind(controller));
  app.post('/admin/invites/:inviteId/resend', controller.resendInvite.bind(controller));
  app.delete('/admin/invites/:inviteId', controller.cancelInvite.bind(controller));
}
