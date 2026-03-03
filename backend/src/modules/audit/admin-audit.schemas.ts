/**
 * backend/src/modules/audit/admin-audit.schemas.ts
 *
 * WHY:
 * - Centralizes request validation for GET /admin/audit-events.
 * - Keeps controller clean: parse + basic validation only.
 *
 * RULES:
 * - limit is NOT validated with a max. The controller clamps it to 100 (ergonomic API).
 * - All datetime params validated as ISO 8601 strings.
 * - userId validated as UUID — malformed IDs never reach the DAL.
 * - tenantId is NOT returned in response rows (always the session tenant).
 */

import { z } from 'zod';

export const auditEventsQuerySchema = z.object({
  // NOTE: Upper bound is enforced via clamping (controller), not schema validation.
  limit: z.coerce.number().int().min(1).default(50),
  offset: z.coerce.number().int().min(0).default(0),
  action: z.string().optional(),
  userId: z.string().uuid('userId must be a valid UUID').optional(),
  from: z.string().datetime({ message: 'from must be a valid ISO 8601 datetime' }).optional(),
  to: z.string().datetime({ message: 'to must be a valid ISO 8601 datetime' }).optional(),
});

export type AuditEventsQuery = z.infer<typeof auditEventsQuerySchema>;

/**
 * Shape of a single audit event returned to the client.
 * tenantId is intentionally omitted — it is always the session tenant.
 * ip + userAgent are included — admin-only forensic data.
 */
export const AuditEventDtoSchema = z.object({
  id: z.string().uuid(),
  action: z.string(),
  userId: z.string().uuid().nullable(),
  membershipId: z.string().uuid().nullable(),
  requestId: z.string().nullable(),
  ip: z.string().nullable(),
  userAgent: z.string().nullable(),
  metadata: z.record(z.unknown()),
  createdAt: z.string(),
});

export type AuditEventDto = z.infer<typeof AuditEventDtoSchema>;
