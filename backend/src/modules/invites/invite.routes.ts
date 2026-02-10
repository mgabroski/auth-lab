/**
 * backend/src/modules/invites/invite.routes.ts
 *
 * WHY:
 * - Declares Invites module endpoints.
 * - Keeps routing separate from controller logic.
 *
 * SECURITY:
 * - Tokens only in POST body (not URL/query).
 *
 * RULES:
 * - No business logic here.
 */

import type { FastifyInstance } from 'fastify';
import type { InviteController } from './invite.controller';

export function registerInviteRoutes(app: FastifyInstance, controller: InviteController) {
  app.post('/auth/invites/accept', controller.acceptInvite.bind(controller));
}
