/**
 * backend/src/modules/people-teams/people-teams.controller.ts
 *
 * WHY:
 * - Maps HTTP requests to the PeopleTeamsService.
 * - Enforces the current shipped ADMIN + MFA + verified-email guard.
 *
 * RULES:
 * - No business logic here.
 * - No DB access here.
 * - Current MEMBER users are denied; future Agent/User runtime roles are not shipped yet.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../shared/http/errors';
import { requireSession } from '../../shared/http/require-auth-context';
import {
  createPeopleTeamGroupSchema,
  peopleTeamsEmptyQuerySchema,
  peopleTeamsGroupIdParamSchema,
  updatePeopleTeamGroupSchema,
} from './people-teams.schemas';
import type { PeopleTeamsService } from './people-teams.service';
import type { PeopleTeamAuditContext } from './people-teams.types';

export class PeopleTeamsController {
  constructor(private readonly peopleTeamsService: PeopleTeamsService) {}

  private requireAdmin(req: FastifyRequest): PeopleTeamAuditContext {
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

  async listGroups(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsed = peopleTeamsEmptyQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.peopleTeamsService.listGroups(auth.tenantId);
    return reply.status(200).send(dto);
  }

  async getGroup(req: FastifyRequest<{ Params: { groupId: string } }>, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsed = peopleTeamsGroupIdParamSchema.safeParse(req.params);

    if (!parsed.success) {
      throw AppError.validationError('Invalid groupId', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.peopleTeamsService.getGroup(auth.tenantId, parsed.data.groupId);
    return reply.status(200).send(dto);
  }

  async listPeople(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsed = peopleTeamsEmptyQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.peopleTeamsService.listPeople(auth.tenantId);
    return reply.status(200).send(dto);
  }

  async createGroup(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsed = createPeopleTeamGroupSchema.safeParse(req.body);

    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.peopleTeamsService.createGroup(auth, parsed.data);
    return reply.status(201).send(dto);
  }

  async updateGroup(req: FastifyRequest<{ Params: { groupId: string } }>, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsedParams = peopleTeamsGroupIdParamSchema.safeParse(req.params);
    const parsedBody = updatePeopleTeamGroupSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      throw AppError.validationError('Invalid request body', {
        issues: [
          ...(parsedParams.success ? [] : parsedParams.error.issues),
          ...(parsedBody.success ? [] : parsedBody.error.issues),
        ],
      });
    }

    const dto = await this.peopleTeamsService.updateGroup(
      auth,
      parsedParams.data.groupId,
      parsedBody.data,
    );
    return reply.status(200).send(dto);
  }

  async archiveGroup(req: FastifyRequest<{ Params: { groupId: string } }>, reply: FastifyReply) {
    const auth = this.requireAdmin(req);
    const parsed = peopleTeamsGroupIdParamSchema.safeParse(req.params);

    if (!parsed.success) {
      throw AppError.validationError('Invalid groupId', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.peopleTeamsService.archiveGroup(auth, parsed.data.groupId);
    return reply.status(200).send(dto);
  }
}
