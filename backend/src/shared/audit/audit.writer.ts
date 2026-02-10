/**
 * backend/src/shared/audit/audit.writer.ts
 *
 * WHY:
 * - Binds request-level context ONCE so services don't repeat it on every audit call.
 * - Supports progressive context enrichment via withContext():
 *     start of tx  → requestId, ip, userAgent
 *     after tenant → + tenantId
 *     after auth   → + userId, membershipId
 *   Each call returns a NEW immutable writer (no mutation).
 * - Thin wrapper over AuditRepo: adds no business logic.
 *
 * RULES:
 * - No module types imported here (shared must stay module-agnostic).
 * - No business rules.
 * - No AppError.
 * - Context is immutable once created — withContext() returns a new instance.
 */

import type { AuditRepo } from './audit.repo';
import type { AuditAction, AuditContext, AuditMetadata } from './audit.types';

const EMPTY_CONTEXT: AuditContext = {
  tenantId: null,
  userId: null,
  membershipId: null,
  requestId: null,
  ip: null,
  userAgent: null,
};

export class AuditWriter {
  private readonly repo: AuditRepo;
  private readonly context: Readonly<AuditContext>;

  constructor(repo: AuditRepo, context?: Partial<AuditContext>) {
    this.repo = repo;
    this.context = Object.freeze({ ...EMPTY_CONTEXT, ...context });
  }

  /**
   * Returns a NEW writer with merged context.
   * Existing fields are preserved; provided fields override.
   *
   * Usage:
   *   const audit = new AuditWriter(repo, { requestId, ip, userAgent });
   *   const withTenant = audit.withContext({ tenantId: tenant.id });
   *   const withUser = withTenant.withContext({ userId: user.id });
   */
  withContext(extra: Partial<AuditContext>): AuditWriter {
    return new AuditWriter(this.repo, { ...this.context, ...extra });
  }

  /**
   * Appends an audit event with the bound context.
   * Only action + metadata change per call.
   */
  async append(action: AuditAction, metadata?: AuditMetadata): Promise<void> {
    await this.repo.append({
      ...this.context,
      action,
      metadata,
    });
  }
}
