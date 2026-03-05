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
 * - requireSession({ role: 'ADMIN', requireMfa: true, requireEmailVerified: true }) — locked guard.
 * - Validate query params with Zod; throw AppError.validationError on failure.
 *
 * X7 — Strict reject, not silent clamp:
 * - The Math.min(parsed.data.limit, 100) clamp is removed. The schema's .max(100)
 *   now owns this boundary. limit=101 returns 400, not silently-clamped 100 items.
 * - parsed.data.limit is passed directly to the service.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../shared/http/errors';
import { requireSession } from '../../shared/http/require-auth-context';
import { auditEventsQuerySchema } from './admin-audit.schemas';
import type { AdminAuditService } from './admin-audit.service';

export class AdminAuditController {
  constructor(private readonly adminAuditService: AdminAuditService) {}

  async listEvents(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req, {
      role: 'ADMIN',
      requireMfa: true,
      requireEmailVerified: true,
    });

    const parsed = auditEventsQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      throw AppError.validationError('Invalid query parameters', {
        issues: parsed.error.issues,
      });
    }

    // X7: Zod schema enforces .max(100) — no manual clamp needed here.
    // limit=101 is rejected with 400 before reaching this line.
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
