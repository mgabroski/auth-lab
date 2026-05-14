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
import { peopleTeamsEmptyQuerySchema } from './people-teams.schemas';
import type { PeopleTeamsService } from './people-teams.service';

export class PeopleTeamsController {
  constructor(private readonly peopleTeamsService: PeopleTeamsService) {}

  private requireAdmin(req: FastifyRequest): { tenantId: string } {
    return requireSession(req, {
      role: 'ADMIN',
      requireMfa: true,
      requireEmailVerified: true,
    });
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
}
