/**
 * backend/src/shared/audit/audit.types.ts
 *
 * WHY:
 * - Central audit event types (compliance trail stored in DB).
 * - Keeps audit writes consistent across all modules.
 *
 * RULES:
 * - Keep types explicit and safe.
 * - Metadata is a plain object (repo serializes to JSON for DB).
 */

export type AuditAction = string;

export type AuditMetadata = Record<string, unknown>;

export type AuditEventInsert = {
  action: AuditAction;

  tenantId: string | null;
  userId: string | null;
  membershipId: string | null;

  requestId: string | null;
  ip: string | null;
  userAgent: string | null;

  metadata?: AuditMetadata;
};
