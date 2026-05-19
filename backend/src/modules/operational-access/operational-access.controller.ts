/**
 * backend/src/modules/operational-access/operational-access.controller.ts
 *
 * WHY:
 * - Maps HTTP requests to the OperationalAccessService.
 * - Enforces the current shipped ADMIN + MFA + verified-email guard.
 *
 * RULES:
 * - No business logic here.
 * - AGENT and USER sessions are denied for this admin-only configuration surface.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../shared/http/errors';
import { requireSession } from '../../shared/http/require-auth-context';
import {
  operationalAccessEmptyQuerySchema,
  operationalAccessGroupIdParamSchema,
  saveOperationalAccessGroupGrantsSchema,
  saveOperationalAccessResponsibleForSchema,
} from './operational-access.schemas';
import type { OperationalAccessService } from './operational-access.service';
import type { OperationalAccessAuditContext } from './operational-access.types';

export class OperationalAccessController {
  constructor(private readonly operationalAccessService: OperationalAccessService) {}

  private requireAdmin(req: FastifyRequest): OperationalAccessAuditContext {
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

  async getCatalog(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsed = operationalAccessEmptyQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.operationalAccessService.getCatalog(auth.tenantId);
    return reply.status(200).send(dto);
  }

  async listGroups(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsed = operationalAccessEmptyQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.operationalAccessService.listGroups(auth.tenantId);
    return reply.status(200).send(dto);
  }

  async listPeople(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsed = operationalAccessEmptyQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.operationalAccessService.listPeople(auth.tenantId);
    return reply.status(200).send(dto);
  }

  async getGroup(req: FastifyRequest<{ Params: { groupId: string } }>, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsed = operationalAccessGroupIdParamSchema.safeParse(req.params);

    if (!parsed.success) {
      throw AppError.validationError('Invalid groupId', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.operationalAccessService.getGroupConfiguration(
      auth.tenantId,
      parsed.data.groupId,
    );
    return reply.status(200).send(dto);
  }

  async saveGroupGrants(req: FastifyRequest<{ Params: { groupId: string } }>, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsedParams = operationalAccessGroupIdParamSchema.safeParse(req.params);
    const parsedBody = saveOperationalAccessGroupGrantsSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: [
          ...(parsedParams.success ? [] : parsedParams.error.issues),
          ...(parsedBody.success ? [] : parsedBody.error.issues),
        ],
      });
    }

    const dto = await this.operationalAccessService.saveGroupGrants(
      auth,
      parsedParams.data.groupId,
      parsedBody.data,
    );
    return reply.status(200).send(dto);
  }

  async saveResponsibleFor(
    req: FastifyRequest<{ Params: { groupId: string } }>,
    reply: FastifyReply,
  ) {
    const auth = this.requireAdmin(req);
    const parsedParams = operationalAccessGroupIdParamSchema.safeParse(req.params);
    const parsedBody = saveOperationalAccessResponsibleForSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: [
          ...(parsedParams.success ? [] : parsedParams.error.issues),
          ...(parsedBody.success ? [] : parsedBody.error.issues),
        ],
      });
    }

    const dto = await this.operationalAccessService.saveResponsibleFor(
      auth,
      parsedParams.data.groupId,
      parsedBody.data,
    );
    return reply.status(200).send(dto);
  }
}
