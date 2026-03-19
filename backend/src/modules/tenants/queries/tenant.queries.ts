/**
 * backend/src/modules/tenants/queries/tenant.queries.ts
 *
 * WHY:
 * - Queries are read-only and side-effect free.
 * - They shape DB rows into Tenant domain types.
 *
 * RULES:
 * - Read-only.
 * - Tenant-scoped when applicable.
 * - No AppError.
 *
 * BRICK 12 UPDATE:
 * - Added getTenantById for admin flows that have tenantId from session
 *   and need to load tenant details (allowedEmailDomains, isActive, etc.).
 *
 * PHASE 1A UPDATE:
 * - Hydrates adminInviteRequired as an explicit tenant policy input.
 *
 * PHASE 9 UPDATE (ADR 0003):
 * - Hydrates setupCompletedAt from setup_completed_at column.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { JsonValue } from '../../../shared/db/database.types';
import type {
  Tenant,
  TenantAllowedEmailDomains,
  TenantAllowedSso,
  TenantKey,
} from '../tenant.types';
import { findTenantByKeySql, findTenantByIdSql } from '../dal/tenant.query-sql';

function parseAllowedEmailDomains(value: JsonValue): TenantAllowedEmailDomains {
  if (!Array.isArray(value)) return [];

  const out: string[] = [];
  for (const v of value) {
    if (typeof v === 'string') {
      const s = v.trim().toLowerCase();
      if (s.length) out.push(s);
    }
  }
  return out;
}

function parseAllowedSso(value: unknown): TenantAllowedSso {
  if (!Array.isArray(value)) return [];

  const out: string[] = [];
  for (const v of value) {
    if (typeof v === 'string') {
      const s = v.trim().toLowerCase();
      if (s.length) out.push(s);
    }
  }
  return out;
}

function rowToTenant(row: Awaited<ReturnType<typeof findTenantByKeySql>>): Tenant | undefined {
  if (!row) return undefined;

  const setupAt = row.setup_completed_at;

  return {
    id: row.id,
    key: row.key,
    name: row.name,

    isActive: row.is_active,
    publicSignupEnabled: row.public_signup_enabled,
    adminInviteRequired: row.admin_invite_required,
    memberMfaRequired: row.member_mfa_required,
    allowedEmailDomains: parseAllowedEmailDomains(row.allowed_email_domains),
    allowedSso: parseAllowedSso(row.allowed_sso),

    // Phase 9: normalise to Date | null regardless of driver return type.
    setupCompletedAt:
      setupAt == null ? null : setupAt instanceof Date ? setupAt : new Date(setupAt as string),

    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function getTenantByKey(
  db: DbExecutor,
  tenantKey: TenantKey,
): Promise<Tenant | undefined> {
  const row = await findTenantByKeySql(db, tenantKey);
  return rowToTenant(row);
}

export async function getTenantById(db: DbExecutor, tenantId: string): Promise<Tenant | undefined> {
  const row = await findTenantByIdSql(db, tenantId);
  return rowToTenant(row);
}
