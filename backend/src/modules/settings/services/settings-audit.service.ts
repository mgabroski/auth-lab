/**
 * backend/src/modules/settings/services/settings-audit.service.ts
 *
 * WHY:
 * - Thin adapter over the shared audit infrastructure for Settings writes.
 * - Preserves the existing repo-wide two-phase audit pattern:
 *   success inside the transaction, failure outside rollback.
 */

import type { AuditRepo } from '../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../shared/audit/audit.writer';
import {
  auditAccessAcknowledged,
  auditAccessAcknowledgeFailed,
  type SettingsAuditRequestContext,
} from '../settings.audit';

export class SettingsAuditService {
  constructor(private readonly auditRepo: AuditRepo) {}

  withAuditRepo(auditRepo: AuditRepo): SettingsAuditService {
    return new SettingsAuditService(auditRepo);
  }

  buildWriter(context: SettingsAuditRequestContext): AuditWriter {
    return new AuditWriter(this.auditRepo, {
      requestId: context.requestId,
      ip: context.ip,
      userAgent: context.userAgent,
      tenantId: context.tenantId,
      userId: context.userId,
      membershipId: context.membershipId,
    });
  }

  async recordAccessAcknowledged(params: {
    writer: AuditWriter;
    tenantId: string;
    sectionVersion: number;
    cpRevision: number;
    status: string;
    aggregateStatus: string;
  }): Promise<void> {
    await auditAccessAcknowledged(params.writer, {
      tenantId: params.tenantId,
      sectionVersion: params.sectionVersion,
      cpRevision: params.cpRevision,
      status: params.status,
      aggregateStatus: params.aggregateStatus,
    });
  }

  async recordAccessAcknowledgeFailed(params: {
    context: SettingsAuditRequestContext;
    errorCode: string;
    message: string;
    expectedVersion: number;
    expectedCpRevision: number;
  }): Promise<void> {
    const writer = this.buildWriter(params.context);
    await auditAccessAcknowledgeFailed(writer, {
      tenantId: params.context.tenantId,
      errorCode: params.errorCode,
      message: params.message,
      expectedVersion: params.expectedVersion,
      expectedCpRevision: params.expectedCpRevision,
    });
  }
}
