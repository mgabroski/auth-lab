/**
 * backend/src/modules/audit/admin-audit.schemas.ts
 *
 * WHY:
 * - Centralizes request validation for GET /admin/audit-events.
 * - Keeps controller clean: parse + basic validation only.
 *
 * RULES:
 * - limit is validated with .max(100) — out-of-range values return 400.
 * - All datetime params validated as ISO 8601 strings.
 * - userId validated as UUID — malformed IDs never reach the DAL.
 * - tenantId is NOT returned in response rows (always the session tenant).
 *
 * X7 — Strict reject, not silent clamp:
 * - Previously: schema had no upper bound on limit; the controller silently
 *   clamped limit=101 → 100. Silent behavior changes on a security-sensitive
 *   admin endpoint are inconsistent with the system-wide strict-validation pattern.
 * - Fix: add .max(100) directly to the schema. Passing limit=101 now returns
 *   400 VALIDATION_ERROR. The Math.min() clamp in the controller is removed.
 * - The NOTE comment about clamping is removed — it described the old contract.
 */

import { z } from 'zod';

export const auditEventsQuerySchema = z.object({
  limit: z.coerce
    .number()
    .int()
    .min(1)
    .max(100, { message: 'limit must be between 1 and 100' })
    .default(50),
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
