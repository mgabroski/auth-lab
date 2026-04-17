/**
 * backend/src/modules/control-plane/accounts/cp-accounts.audit.ts
 *
 * WHY:
 * - Typed audit helpers for the Control Plane accounts module.
 * - Keeps CP audit metadata consistent for the mutation flows that matter now.
 *
 * RULES:
 * - No DB access here (delegates to AuditWriter).
 * - No business rules.
 * - Never log secrets or raw credential material.
 */

import type { AuditWriter } from '../../../shared/audit/audit.writer';

export type CpAuditRequestContext = {
  requestId: string | null;
  ip: string | null;
  userAgent: string | null;
};

export function auditCpAccountCreated(
  writer: AuditWriter,
  data: { accountId: string; accountKey: string; cpRevision: number },
): Promise<void> {
  return writer.append('cp.account.created', {
    accountId: data.accountId,
    accountKey: data.accountKey,
    cpRevision: data.cpRevision,
  });
}

export function auditCpAccountPublished(
  writer: AuditWriter,
  data: {
    accountId: string;
    accountKey: string;
    targetStatus: 'Active' | 'Disabled';
    cpRevision: number;
    tenantId: string | null;
  },
): Promise<void> {
  return writer.append('cp.account.published', {
    accountId: data.accountId,
    accountKey: data.accountKey,
    targetStatus: data.targetStatus,
    cpRevision: data.cpRevision,
    tenantId: data.tenantId,
  });
}

export function auditCpAccountStatusToggled(
  writer: AuditWriter,
  data: {
    accountId: string;
    accountKey: string;
    targetStatus: 'Active' | 'Disabled';
    cpRevision: number;
    tenantId: string | null;
  },
): Promise<void> {
  return writer.append('cp.account.status_toggled', {
    accountId: data.accountId,
    accountKey: data.accountKey,
    targetStatus: data.targetStatus,
    cpRevision: data.cpRevision,
    tenantId: data.tenantId,
  });
}
