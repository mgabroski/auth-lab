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
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { JsonValue } from '../../../shared/db/database.types';
import type { Tenant, TenantAllowedEmailDomains, TenantKey } from '../tenant.types';
import { findTenantByKeySql } from '../dal/tenant.query-sql';

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

export async function getTenantByKey(
  db: DbExecutor,
  tenantKey: TenantKey,
): Promise<Tenant | undefined> {
  const row = await findTenantByKeySql(db, tenantKey);
  if (!row) return undefined;

  return {
    id: row.id,
    key: row.key,
    name: row.name,

    isActive: row.is_active,
    publicSignupEnabled: row.public_signup_enabled,
    memberMfaRequired: row.member_mfa_required,
    allowedEmailDomains: parseAllowedEmailDomains(row.allowed_email_domains),

    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
