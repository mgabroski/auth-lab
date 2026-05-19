/**
 * backend/src/modules/operational-access/operational-access.controller.ts
 *
 * WHY:
 * - Maps HTTP requests to the OperationalAccessService.
 * - Enforces ADMIN + MFA + verified-email for configuration routes.
 * - Runtime proof routes accept authenticated members and delegate allow/deny
 *   decisions to the backend Operational Access resolver.
 *
 * RULES:
 * - No business logic here.
 * - AGENT and USER sessions remain denied for admin-only configuration routes.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../shared/http/errors';
import { requireSession, type RequiredAuthContext } from '../../shared/http/require-auth-context';
import {
  operationalAccessEmptyQuerySchema,
  operationalAccessGroupIdParamSchema,
  operationalAccessMembershipIdParamSchema,
  saveOperationalAccessGroupGrantsSchema,
  saveOperationalAccessOversightSchema,
  saveOperationalAccessResponsibleForSchema,
  saveOperationalAccessSpecialAccessSchema,
  saveOperationalAccessTemporaryCoverageSchema,
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

  private requireRuntimeActor(req: FastifyRequest): RequiredAuthContext {
    const auth = requireSession(req, {
      requireEmailVerified: true,
    });

    if (auth.role === 'ADMIN' && auth.mfaVerified !== true) {
      throw AppError.forbidden('MFA verification required.');
    }

    return auth;
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

  async listAdvancedCoverage(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsed = operationalAccessEmptyQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.operationalAccessService.listAdvancedCoverage(auth.tenantId);
    return reply.status(200).send(dto);
  }

  async saveOversight(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsedBody = saveOperationalAccessOversightSchema.safeParse(req.body);

    if (!parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsedBody.error.issues,
      });
    }

    const dto = await this.operationalAccessService.saveOversight(auth, parsedBody.data);
    return reply.status(200).send(dto);
  }

  async saveTemporaryCoverage(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsedBody = saveOperationalAccessTemporaryCoverageSchema.safeParse(req.body);

    if (!parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsedBody.error.issues,
      });
    }

    const dto = await this.operationalAccessService.saveTemporaryCoverage(auth, parsedBody.data);
    return reply.status(200).send(dto);
  }

  async saveSpecialAccess(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsedBody = saveOperationalAccessSpecialAccessSchema.safeParse(req.body);

    if (!parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsedBody.error.issues,
      });
    }

    const dto = await this.operationalAccessService.saveSpecialAccess(auth, parsedBody.data);
    return reply.status(200).send(dto);
  }

  async listRuntimePeople(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireRuntimeActor(req);
    const parsed = operationalAccessEmptyQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.operationalAccessService.listRuntimePeople({
      tenantId: auth.tenantId,
      userId: auth.userId,
      membershipId: auth.membershipId,
      role: auth.role,
    });
    return reply.status(200).send(dto);
  }

  async getRuntimePerson(
    req: FastifyRequest<{ Params: { membershipId: string } }>,
    reply: FastifyReply,
  ) {
    const auth = this.requireRuntimeActor(req);
    const parsedParams = operationalAccessMembershipIdParamSchema.safeParse(req.params);

    if (!parsedParams.success) {
      throw AppError.validationError('Invalid membershipId', {
        issues: parsedParams.error.issues,
      });
    }

    const dto = await this.operationalAccessService.getRuntimePerson(
      {
        tenantId: auth.tenantId,
        userId: auth.userId,
        membershipId: auth.membershipId,
        role: auth.role,
      },
      parsedParams.data.membershipId,
    );
    return reply.status(200).send(dto);
  }
}
