/**
 * backend/src/modules/settings/settings.routes.ts
 *
 * WHY:
 * - Declares the currently shipped Settings HTTP surface for Step 10 Phase 2.
 * - Keeps the first Settings-native read routes explicit while the later write
 *   and page-specific routes remain intentionally unimplemented.
 */

import type { FastifyInstance } from 'fastify';
import { SettingsController } from './settings.controller';

export function registerSettingsRoutes(app: FastifyInstance, controller: SettingsController): void {
  app.get('/settings/bootstrap', controller.getBootstrap.bind(controller));
  app.get('/settings/overview', controller.getOverview.bind(controller));
}
