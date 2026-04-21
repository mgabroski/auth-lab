/**
 * backend/src/modules/settings/settings.routes.ts
 *
 * WHY:
 * - Declares the currently shipped Settings HTTP surface.
 * - Keeps the live Settings-native reads and the first Access acknowledge write
 *   explicit while later section writes remain intentionally unimplemented.
 */

import type { FastifyInstance } from 'fastify';
import { SettingsController } from './settings.controller';

export function registerSettingsRoutes(app: FastifyInstance, controller: SettingsController): void {
  app.get('/settings/bootstrap', controller.getBootstrap.bind(controller));
  app.get('/settings/overview', controller.getOverview.bind(controller));
  app.get('/settings/access', controller.getAccess.bind(controller));
  app.post('/settings/access/acknowledge', controller.acknowledgeAccess.bind(controller));
}
