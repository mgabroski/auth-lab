/**
 * backend/src/modules/settings/settings.audit.ts
 *
 * WHY:
 * - Typed audit helpers for the Settings module.
 * - Keeps Settings success/failure audit metadata consistent.
 *
 * RULES:
 * - No DB access here (delegates to AuditWriter).
 * - No business rules.
 */

import type { AuditWriter } from '../../shared/audit/audit.writer';
import type { SettingsAccountCardKey } from './settings.types';

export type SettingsAuditRequestContext = {
  requestId: string | null;
  ip: string | null;
  userAgent: string | null;
  tenantId: string;
  userId: string;
  membershipId: string;
};

function accountCardSavedAction(cardKey: SettingsAccountCardKey): string {
  switch (cardKey) {
    case 'branding':
      return 'settings.account.branding.saved';
    case 'orgStructure':
      return 'settings.account.org_structure.saved';
    case 'calendar':
      return 'settings.account.calendar.saved';
    default: {
      const exhaustiveCheck: never = cardKey;
      return exhaustiveCheck;
    }
  }
}

function accountCardFailedAction(cardKey: SettingsAccountCardKey): string {
  switch (cardKey) {
    case 'branding':
      return 'settings.account.branding.save.failed';
    case 'orgStructure':
      return 'settings.account.org_structure.save.failed';
    case 'calendar':
      return 'settings.account.calendar.save.failed';
    default: {
      const exhaustiveCheck: never = cardKey;
      return exhaustiveCheck;
    }
  }
}

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

export function auditAccountCardSaved(
  writer: AuditWriter,
  data: {
    tenantId: string;
    cardKey: SettingsAccountCardKey;
    cardVersion: number;
    sectionVersion: number;
    cpRevision: number;
    sectionStatus: string;
    aggregateStatus: string;
  },
): Promise<void> {
  return writer.append(accountCardSavedAction(data.cardKey), {
    tenantId: data.tenantId,
    cardKey: data.cardKey,
    cardVersion: data.cardVersion,
    sectionVersion: data.sectionVersion,
    cpRevision: data.cpRevision,
    sectionStatus: data.sectionStatus,
    aggregateStatus: data.aggregateStatus,
  });
}

export function auditAccountCardSaveFailed(
  writer: AuditWriter,
  data: {
    tenantId: string;
    cardKey: SettingsAccountCardKey;
    errorCode: string;
    message: string;
    expectedVersion: number;
    expectedCpRevision: number;
  },
): Promise<void> {
  return writer.append(accountCardFailedAction(data.cardKey), {
    tenantId: data.tenantId,
    cardKey: data.cardKey,
    errorCode: data.errorCode,
    message: data.message,
    expectedVersion: data.expectedVersion,
    expectedCpRevision: data.expectedCpRevision,
  });
}
