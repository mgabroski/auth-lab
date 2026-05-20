/**
 * backend/src/modules/personal-cards/personal-cards.controller.ts
 *
 * WHY:
 * - Implements the narrow Personal Cards read model used as the first real
 *   Operational Access module-consumer proof.
 * - The API surface is intentionally tiny: list cards and read one card.
 *
 * RULES:
 * - Frontend receives already-masked DTOs and server-returned Why/sourcePath.
 * - The controller never computes effective access; it authenticates and
 *   delegates to PersonalCardsService.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../shared/http/errors';
import { requireSession, type RequiredAuthContext } from '../../shared/http/require-auth-context';
import {
  operationalAccessEmptyQuerySchema,
  operationalAccessMembershipIdParamSchema,
} from '../operational-access/operational-access.schemas';
import type { OperationalAccessResolveActor } from '../operational-access/operational-access.types';
import type { PersonalCardsService } from './personal-cards.service';

export class PersonalCardsController {
  constructor(private readonly personalCardsService: PersonalCardsService) {}

  private requireRuntimeActor(req: FastifyRequest): RequiredAuthContext {
    const auth = requireSession(req, {
      requireEmailVerified: true,
    });

    if (auth.role === 'ADMIN' && auth.mfaVerified !== true) {
      throw AppError.forbidden('MFA verification required.');
    }

    return auth;
  }

  private toResolveActor(auth: RequiredAuthContext): OperationalAccessResolveActor {
    return {
      tenantId: auth.tenantId,
      userId: auth.userId,
      membershipId: auth.membershipId,
      role: auth.role,
    };
  }

  async listCards(req: FastifyRequest, reply: FastifyReply) {
    const auth = this.requireRuntimeActor(req);
    const parsed = operationalAccessEmptyQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', {
        issues: parsed.error.issues,
      });
    }

    const dto = await this.personalCardsService.listCards(this.toResolveActor(auth));
    return reply.status(200).send(dto);
  }

  async getCard(req: FastifyRequest<{ Params: { membershipId: string } }>, reply: FastifyReply) {
    const auth = this.requireRuntimeActor(req);
    const parsedParams = operationalAccessMembershipIdParamSchema.safeParse(req.params);

    if (!parsedParams.success) {
      throw AppError.validationError('Invalid membershipId', {
        issues: parsedParams.error.issues,
      });
    }

    const dto = await this.personalCardsService.getCard(
      this.toResolveActor(auth),
      parsedParams.data.membershipId,
    );

    return reply.status(200).send(dto);
  }
}
