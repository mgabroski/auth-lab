/**
 * backend/src/modules/operational-access/operational-access.audit.ts
 *
 * WHY:
 * - Typed audit helpers for Operational Access configuration writes.
 * - Keeps audit action names consistent while the shared AuditWriter remains generic.
 *
 * RULES:
 * - Audit configuration changes only.
 * - Do not claim runtime access decisions were resolved or granted.
 */

import type { AuditWriter } from '../../shared/audit/audit.writer';
import type {
  OperationalAccessGroupGrantDto,
  OperationalAccessResponsibleForAssignmentDto,
} from './operational-access.types';

type OperationalAccessGroupAuditSummary = {
  id: string;
  name: string;
  level: 'AGENT';
};

export function auditOperationalAccessGroupGrantsSaved(
  writer: AuditWriter,
  data: {
    group: OperationalAccessGroupAuditSummary;
    before: OperationalAccessGroupGrantDto[];
    after: OperationalAccessGroupGrantDto[];
    source: string;
  },
): Promise<void> {
  return writer.append('operational_access.group_grants_saved', {
    source: data.source,
    group: data.group,
    before: data.before,
    after: data.after,
    runtimeVisibilityChanged: false,
  });
}

export function auditOperationalAccessResponsibleForSaved(
  writer: AuditWriter,
  data: {
    group: OperationalAccessGroupAuditSummary;
    before: OperationalAccessResponsibleForAssignmentDto[];
    after: OperationalAccessResponsibleForAssignmentDto[];
    source: string;
  },
): Promise<void> {
  return writer.append('operational_access.responsible_for_saved', {
    source: data.source,
    group: data.group,
    before: data.before,
    after: data.after,
    runtimeVisibilityChanged: false,
  });
}
