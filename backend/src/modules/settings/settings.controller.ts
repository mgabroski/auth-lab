/**
 * backend/src/modules/settings/settings.controller.ts
 *
 * WHY:
 * - Maps HTTP requests to the Phase 2 Settings read services.
 * - Enforces the locked ADMIN + MFA + email-verified guard for the first
 *   Settings-native read surfaces.
 *
 * RULES:
 * - No business logic here.
 * - No DB access here.
 * - Settings bootstrap and overview are tenant-scoped authenticated reads only.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { requireSession } from '../../shared/http/require-auth-context';
import { SettingsBootstrapService } from './services/settings-bootstrap.service';
import { SettingsOverviewService } from './services/settings-overview.service';

export class SettingsController {
  constructor(
    private readonly bootstrapService: SettingsBootstrapService,
    private readonly overviewService: SettingsOverviewService,
  ) {}

  async getBootstrap(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req, {
      role: 'ADMIN',
      requireMfa: true,
      requireEmailVerified: true,
    });

    const dto = await this.bootstrapService.getBootstrap(auth.tenantId);
    return reply.status(200).send(dto);
  }

  async getOverview(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req, {
      role: 'ADMIN',
      requireMfa: true,
      requireEmailVerified: true,
    });

    const dto = await this.overviewService.getOverview(auth.tenantId);
    return reply.status(200).send(dto);
  }
}
