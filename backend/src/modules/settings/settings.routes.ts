/**
 * backend/src/modules/settings/settings.routes.ts
 *
 * WHY:
 * - Declares the currently shipped Settings HTTP surface.
 * - Keeps the live Settings-native reads and explicit write boundaries
 *   discoverable while deferred sections remain intentionally absent.
 */

import type { FastifyInstance } from 'fastify';
import { SettingsController } from './settings.controller';

export function registerSettingsRoutes(app: FastifyInstance, controller: SettingsController): void {
  app.get('/settings/bootstrap', controller.getBootstrap.bind(controller));
  app.get('/settings/overview', controller.getOverview.bind(controller));
  app.get('/settings/access', controller.getAccess.bind(controller));
  app.post('/settings/access/acknowledge', controller.acknowledgeAccess.bind(controller));
  app.get('/settings/account', controller.getAccount.bind(controller));
  app.put('/settings/account/branding', controller.saveAccountBranding.bind(controller));
  app.put('/settings/account/org-structure', controller.saveAccountOrgStructure.bind(controller));
  app.put('/settings/account/calendar', controller.saveAccountCalendar.bind(controller));
}
