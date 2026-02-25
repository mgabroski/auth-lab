/**
 * backend/src/modules/audit/admin-audit.routes.ts
 *
 * WHY:
 * - Declares the audit viewer admin endpoint.
 * - Keeps routing separate from controller logic.
 *
 * RULES:
 * - No business logic here.
 */

import type { FastifyInstance } from 'fastify';
import type { AdminAuditController } from './admin-audit.controller';

export function registerAdminAuditRoutes(
  app: FastifyInstance,
  controller: AdminAuditController,
): void {
  app.get('/admin/audit-events', controller.listEvents.bind(controller));
}
