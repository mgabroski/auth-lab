/**
 * backend/src/modules/invites/admin/admin-invite.controller.ts
 *
 * WHY:
 * - Maps HTTP → AdminInviteService calls for all admin invite endpoints.
 * - Enforces session + role + MFA guards at the controller boundary.
 *
 * RULES:
 * - No business rules here.
 * - No DB access here.
 * - requireSession({ role: 'ADMIN', requireMfa: true }) on every handler.
 * - Validate with Zod; throw AppError.validationError on parse failure.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../../shared/http/errors';
import { requireSession } from '../../../shared/http/require-auth-context';
import { createInviteSchema, inviteIdParamSchema, listInvitesSchema } from './admin-invite.schemas';
import type { AdminInviteService } from './admin-invite.service';

export class AdminInviteController {
  constructor(private readonly adminInviteService: AdminInviteService) {}

  async createInvite(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req, { role: 'ADMIN', requireMfa: true });

    const parsed = createInviteSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', { issues: parsed.error.issues });
    }

    const tenantKey = req.requestContext.tenantKey;
    if (!tenantKey) {
      throw AppError.validationError('Missing tenant context');
    }

    const invite = await this.adminInviteService.createInvite({
      tenantId: auth.tenantId,
      userId: auth.userId,
      tenantKey,
      email: parsed.data.email,
      role: parsed.data.role,
      requestId: req.requestContext.requestId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
    });

    return reply.status(201).send({ invite });
  }

  async listInvites(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req, { role: 'ADMIN', requireMfa: true });

    const parsed = listInvitesSchema.safeParse(req.query);
    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', { issues: parsed.error.issues });
    }

    const { invites, total } = await this.adminInviteService.listInvites({
      tenantId: auth.tenantId,
      userId: auth.userId,
      status: parsed.data.status,
      limit: parsed.data.limit,
      offset: parsed.data.offset,
      requestId: req.requestContext.requestId,
    });

    return reply.status(200).send({
      invites,
      total,
      limit: parsed.data.limit,
      offset: parsed.data.offset,
    });
  }

  async resendInvite(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req, { role: 'ADMIN', requireMfa: true });

    const parsedParams = inviteIdParamSchema.safeParse(req.params);
    if (!parsedParams.success) {
      throw AppError.validationError('Invalid inviteId', { issues: parsedParams.error.issues });
    }

    const tenantKey = req.requestContext.tenantKey;
    if (!tenantKey) {
      throw AppError.validationError('Missing tenant context');
    }

    const invite = await this.adminInviteService.resendInvite({
      inviteId: parsedParams.data.inviteId,
      tenantId: auth.tenantId,
      userId: auth.userId,
      tenantKey,
      requestId: req.requestContext.requestId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
    });

    return reply.status(200).send({ invite });
  }

  async cancelInvite(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req, { role: 'ADMIN', requireMfa: true });

    const parsedParams = inviteIdParamSchema.safeParse(req.params);
    if (!parsedParams.success) {
      throw AppError.validationError('Invalid inviteId', { issues: parsedParams.error.issues });
    }

    await this.adminInviteService.cancelInvite({
      inviteId: parsedParams.data.inviteId,
      tenantId: auth.tenantId,
      userId: auth.userId,
      requestId: req.requestContext.requestId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
    });

    return reply.status(200).send({ status: 'CANCELLED' });
  }
}
