/**
 * backend/src/modules/personal-cards/personal-cards.module.ts
 *
 * WHY:
 * - Wires the first real Personal Cards module proof against the backend
 *   Operational Access resolver.
 * - The module owns the module-facing read model; Operational Access owns
 *   resolver policy and configuration.
 */

import type { FastifyInstance } from 'fastify';
import type { OperationalAccessService } from '../operational-access/operational-access.service';
import { PersonalCardsController } from './personal-cards.controller';
import { registerPersonalCardsRoutes } from './personal-cards.routes';
import { PersonalCardsService } from './personal-cards.service';

export type PersonalCardsModule = ReturnType<typeof createPersonalCardsModule>;

export function createPersonalCardsModule(deps: {
  operationalAccessService: OperationalAccessService;
}) {
  const service = new PersonalCardsService(deps.operationalAccessService);
  const controller = new PersonalCardsController(service);

  return {
    service,
    registerRoutes(app: FastifyInstance) {
      registerPersonalCardsRoutes(app, controller);
    },
  };
}
