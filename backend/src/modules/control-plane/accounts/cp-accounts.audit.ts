/**
 * backend/src/modules/control-plane/accounts/cp-accounts.audit.ts
 *
 * WHY:
 * - Typed audit helpers for the Control Plane accounts module.
 * - Keeps CP audit metadata consistent for the mutation flows that matter now.
 * - Covers both success audits inside the transaction and failure audits outside
 *   the transaction so rollback does not erase the operator trail.
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

type CpAccountMutationFailureData = {
  accountId: string | null;
  accountKey: string;
  errorCode: string;
  message: string;
};

function appendCpStep2SavedAudit(
  writer: AuditWriter,
  action:
    | 'cp.account.access.saved'
    | 'cp.account.account_settings.saved'
    | 'cp.account.modules.saved'
    | 'cp.account.personal.saved'
    | 'cp.account.integrations.saved',
  data: {
    accountId: string;
    accountKey: string;
    cpRevision: number;
    changed: boolean;
  },
): Promise<void> {
  return writer.append(action, {
    accountId: data.accountId,
    accountKey: data.accountKey,
    cpRevision: data.cpRevision,
    changed: data.changed,
  });
}

function appendCpMutationFailureAudit(
  writer: AuditWriter,
  action:
    | 'cp.account.create.failed'
    | 'cp.account.publish.failed'
    | 'cp.account.status_toggle.failed'
    | 'cp.account.access.save.failed'
    | 'cp.account.account_settings.save.failed'
    | 'cp.account.modules.save.failed'
    | 'cp.account.personal.save.failed'
    | 'cp.account.integrations.save.failed',
  data: CpAccountMutationFailureData,
): Promise<void> {
  return writer.append(action, {
    accountId: data.accountId,
    accountKey: data.accountKey,
    errorCode: data.errorCode,
    message: data.message,
  });
}

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

export function auditCpAccountCreateFailed(
  writer: AuditWriter,
  data: CpAccountMutationFailureData,
): Promise<void> {
  return appendCpMutationFailureAudit(writer, 'cp.account.create.failed', data);
}

export function auditCpAccessSaved(
  writer: AuditWriter,
  data: { accountId: string; accountKey: string; cpRevision: number; changed: boolean },
): Promise<void> {
  return appendCpStep2SavedAudit(writer, 'cp.account.access.saved', data);
}

export function auditCpAccessSaveFailed(
  writer: AuditWriter,
  data: CpAccountMutationFailureData,
): Promise<void> {
  return appendCpMutationFailureAudit(writer, 'cp.account.access.save.failed', data);
}

export function auditCpAccountSettingsSaved(
  writer: AuditWriter,
  data: { accountId: string; accountKey: string; cpRevision: number; changed: boolean },
): Promise<void> {
  return appendCpStep2SavedAudit(writer, 'cp.account.account_settings.saved', data);
}

export function auditCpAccountSettingsSaveFailed(
  writer: AuditWriter,
  data: CpAccountMutationFailureData,
): Promise<void> {
  return appendCpMutationFailureAudit(writer, 'cp.account.account_settings.save.failed', data);
}

export function auditCpModuleSettingsSaved(
  writer: AuditWriter,
  data: { accountId: string; accountKey: string; cpRevision: number; changed: boolean },
): Promise<void> {
  return appendCpStep2SavedAudit(writer, 'cp.account.modules.saved', data);
}

export function auditCpModuleSettingsSaveFailed(
  writer: AuditWriter,
  data: CpAccountMutationFailureData,
): Promise<void> {
  return appendCpMutationFailureAudit(writer, 'cp.account.modules.save.failed', data);
}

export function auditCpPersonalSaved(
  writer: AuditWriter,
  data: { accountId: string; accountKey: string; cpRevision: number; changed: boolean },
): Promise<void> {
  return appendCpStep2SavedAudit(writer, 'cp.account.personal.saved', data);
}

export function auditCpPersonalSaveFailed(
  writer: AuditWriter,
  data: CpAccountMutationFailureData,
): Promise<void> {
  return appendCpMutationFailureAudit(writer, 'cp.account.personal.save.failed', data);
}

export function auditCpIntegrationsSaved(
  writer: AuditWriter,
  data: { accountId: string; accountKey: string; cpRevision: number; changed: boolean },
): Promise<void> {
  return appendCpStep2SavedAudit(writer, 'cp.account.integrations.saved', data);
}

export function auditCpIntegrationsSaveFailed(
  writer: AuditWriter,
  data: CpAccountMutationFailureData,
): Promise<void> {
  return appendCpMutationFailureAudit(writer, 'cp.account.integrations.save.failed', data);
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

export function auditCpAccountPublishFailed(
  writer: AuditWriter,
  data: CpAccountMutationFailureData,
): Promise<void> {
  return appendCpMutationFailureAudit(writer, 'cp.account.publish.failed', data);
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

export function auditCpAccountStatusToggleFailed(
  writer: AuditWriter,
  data: CpAccountMutationFailureData,
): Promise<void> {
  return appendCpMutationFailureAudit(writer, 'cp.account.status_toggle.failed', data);
}
