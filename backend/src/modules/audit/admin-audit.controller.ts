/**
 * backend/src/modules/audit/admin-audit.controller.ts
 *
 * WHY:
 * - Maps HTTP → AdminAuditService for the audit events viewer endpoint.
 * - Enforces ADMIN + MFA guard at the controller boundary.
 *
 * RULES:
 * - No business logic here.
 * - No DB access here.
 * - requireSession({ role: 'ADMIN', requireMfa: true }) — locked guard.
 * - Validate query params with Zod; throw AppError.validationError on failure.
 * - limit > 100 → Zod rejects → 400 (no clamping, Comment A locked).
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../shared/http/errors';
import { requireSession } from '../../shared/http/require-auth-context';
import { auditEventsQuerySchema } from './admin-audit.schemas';
import type { AdminAuditService } from './admin-audit.service';

export class AdminAuditController {
  constructor(private readonly adminAuditService: AdminAuditService) {}

  async listEvents(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req, { role: 'ADMIN', requireMfa: true });

    const parsed = auditEventsQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', {
        issues: parsed.error.issues,
      });
    }

    const result = await this.adminAuditService.listEvents({
      tenantId: auth.tenantId,
      action: parsed.data.action,
      userId: parsed.data.userId,
      from: parsed.data.from,
      to: parsed.data.to,
      limit: parsed.data.limit,
      offset: parsed.data.offset,
    });

    return reply.status(200).send(result);
  }
}
