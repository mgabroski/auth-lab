/**
 * backend/src/modules/personal-cards/personal-cards.routes.ts
 *
 * WHY:
 * - Declares the first real module surface that consumes backend-resolved
 *   Operational Access decisions.
 * - Keeps Personal Cards routing separate from the Operational Access admin
 *   configuration API so the proof is a real module integration, not only an
 *   OA-owned resolver endpoint.
 *
 * RULES:
 * - No access decisions are made in routes.
 * - List/detail visibility is delegated to PersonalCardsController, which uses
 *   the backend OperationalAccessService resolver.
 */

import type { FastifyInstance } from 'fastify';
import type { PersonalCardsController } from './personal-cards.controller';

export function registerPersonalCardsRoutes(
  app: FastifyInstance,
  controller: PersonalCardsController,
): void {
  app.get('/personal/cards', controller.listCards.bind(controller));
  app.get('/personal/cards/:membershipId', controller.getCard.bind(controller));
}
