/**
 * backend/src/modules/settings/settings.controller.ts
 *
 * WHY:
 * - Maps HTTP requests to the Settings read and write services.
 * - Enforces the locked ADMIN + MFA + email-verified guard for the shipped
 *   Settings-native surfaces.
 *
 * RULES:
 * - No business logic here.
 * - No DB access here.
 * - Settings reads and writes are tenant-scoped authenticated surfaces only.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../shared/http/errors';
import { requireSession } from '../../shared/http/require-auth-context';
import {
  acknowledgeAccessSettingsSchema,
  saveAccountBrandingSchema,
  saveAccountCalendarSchema,
  saveAccountOrgStructureSchema,
} from './settings.schemas';
import { SettingsBootstrapService } from './services/settings-bootstrap.service';
import { SettingsOverviewService } from './services/settings-overview.service';
import { AccessSettingsReadService } from './services/access-settings-read.service';
import { AccessSettingsService } from './services/access-settings.service';
import { AccountSettingsReadService } from './services/account-settings-read.service';
import { AccountSettingsService } from './services/account-settings.service';
import type { SettingsAuditRequestContext } from './settings.audit';

export class SettingsController {
  constructor(
    private readonly bootstrapService: SettingsBootstrapService,
    private readonly overviewService: SettingsOverviewService,
    private readonly accessReadService: AccessSettingsReadService,
    private readonly accessService: AccessSettingsService,
    private readonly accountReadService: AccountSettingsReadService,
    private readonly accountService: AccountSettingsService,
  ) {}

  private buildAuditContext(req: FastifyRequest): SettingsAuditRequestContext {
    const auth = requireSession(req, {
      role: 'ADMIN',
      requireMfa: true,
      requireEmailVerified: true,
    });

    const userAgentHeader = req.headers['user-agent'];

    return {
      requestId: req.requestContext?.requestId ?? null,
      ip: req.ip ?? null,
      userAgent: typeof userAgentHeader === 'string' ? userAgentHeader : null,
      tenantId: auth.tenantId,
      userId: auth.userId,
      membershipId: auth.membershipId,
    };
  }

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

  async getAccess(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req, {
      role: 'ADMIN',
      requireMfa: true,
      requireEmailVerified: true,
    });

    const dto = await this.accessReadService.getAccessSettings(auth.tenantId);
    return reply.status(200).send(dto);
  }

  async acknowledgeAccess(req: FastifyRequest, reply: FastifyReply) {
    const auditContext = this.buildAuditContext(req);
    const parsed = acknowledgeAccessSettingsSchema.safeParse(req.body);

    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.accessService.acknowledgeAccess(auditContext, parsed.data);
    return reply.status(200).send(dto);
  }

  async getAccount(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req, {
      role: 'ADMIN',
      requireMfa: true,
      requireEmailVerified: true,
    });

    const dto = await this.accountReadService.getAccountSettings(auth.tenantId);
    return reply.status(200).send(dto);
  }

  async saveAccountBranding(req: FastifyRequest, reply: FastifyReply) {
    const auditContext = this.buildAuditContext(req);
    const parsed = saveAccountBrandingSchema.safeParse(req.body);

    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.accountService.saveBranding(auditContext, parsed.data);
    return reply.status(200).send(dto);
  }

  async saveAccountOrgStructure(req: FastifyRequest, reply: FastifyReply) {
    const auditContext = this.buildAuditContext(req);
    const parsed = saveAccountOrgStructureSchema.safeParse(req.body);

    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.accountService.saveOrgStructure(auditContext, parsed.data);
    return reply.status(200).send(dto);
  }

  async saveAccountCalendar(req: FastifyRequest, reply: FastifyReply) {
    const auditContext = this.buildAuditContext(req);
    const parsed = saveAccountCalendarSchema.safeParse(req.body);

    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.accountService.saveCalendar(auditContext, parsed.data);
    return reply.status(200).send(dto);
  }
}
