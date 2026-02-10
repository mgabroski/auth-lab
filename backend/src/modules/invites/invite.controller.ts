/**
 * backend/src/modules/invites/invite.controller.ts
 *
 * WHY:
 * - Maps HTTP -> service call.
 * - Validates request payload and returns response.
 *
 * RULES:
 * - No DB access here.
 * - No business rules here.
 * - Validate with Zod and throw AppError.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { acceptInviteSchema } from './invite.schemas';
import { AppError } from '../../shared/http/errors';
import type { InviteService } from './invite.service';

export class InviteController {
  constructor(private readonly inviteService: InviteService) {}

  async acceptInvite(req: FastifyRequest, reply: FastifyReply) {
    const parsed = acceptInviteSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const result = await this.inviteService.acceptInvite({
      tenantKey: req.requestContext.tenantKey,
      token: parsed.data.token,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
    });

    return reply.status(200).send(result);
  }
}
