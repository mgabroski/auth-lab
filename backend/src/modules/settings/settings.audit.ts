/**
 * backend/src/modules/settings/settings.audit.ts
 *
 * WHY:
 * - Typed audit helpers for the Settings module.
 * - Keeps Access acknowledge success/failure audit metadata consistent.
 *
 * RULES:
 * - No DB access here (delegates to AuditWriter).
 * - No business rules.
 */

import type { AuditWriter } from '../../shared/audit/audit.writer';

export type SettingsAuditRequestContext = {
  requestId: string | null;
  ip: string | null;
  userAgent: string | null;
  tenantId: string;
  userId: string;
  membershipId: string;
};

export function auditAccessAcknowledged(
  writer: AuditWriter,
  data: {
    tenantId: string;
    sectionVersion: number;
    cpRevision: number;
    status: string;
    aggregateStatus: string;
  },
): Promise<void> {
  return writer.append('settings.access.acknowledged', {
    tenantId: data.tenantId,
    sectionVersion: data.sectionVersion,
    cpRevision: data.cpRevision,
    status: data.status,
    aggregateStatus: data.aggregateStatus,
  });
}

export function auditAccessAcknowledgeFailed(
  writer: AuditWriter,
  data: {
    tenantId: string;
    errorCode: string;
    message: string;
    expectedVersion: number;
    expectedCpRevision: number;
  },
): Promise<void> {
  return writer.append('settings.access.acknowledge.failed', {
    tenantId: data.tenantId,
    errorCode: data.errorCode,
    message: data.message,
    expectedVersion: data.expectedVersion,
    expectedCpRevision: data.expectedCpRevision,
  });
}
