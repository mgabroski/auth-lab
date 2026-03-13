/**
 * backend/src/modules/invites/queries/invite.queries.ts
 *
 * WHY:
 * - Queries are read-only and side-effect free.
 * - They shape DB rows into Invites domain types.
 *
 * RULES:
 * - Read-only.
 * - Tenant-scoped when applicable.
 * - No AppError.
 *
 * BRICK 12 UPDATE:
 * - Added getPendingInviteByTenantAndEmail (duplicate guard for createInvite) — PR1.
 * - Added rowToInviteSummary helper (shared by all query functions) — PR1.
 * - Added getInviteByIdAndTenant (resend/cancel lookup) — PR2.
 * - Added listInvitesByTenant (paginated list endpoint) — PR2.
 *
 * PHASE 1B UPDATE:
 * - Added getLatestInviteByTenantAndEmail so auth flows can resolve the latest
 *   invite state for a (tenant, email) policy decision without needing a raw token.
 */

import type { DbExecutor } from '../../../shared/db/db';
import {
  findInviteByTenantAndTokenHashSql,
  findPendingInviteByTenantAndEmailSql,
  findInviteByIdAndTenantSql,
  findInvitesByTenantSql,
  countInvitesByTenantSql,
  findLatestInviteByTenantAndEmailSql,
} from '../dal/invite.query-sql';
import type { Invite, InviteRole, InviteStatus, InviteSummary } from '../invite.types';

function parseInviteStatus(value: string): InviteStatus {
  if (value === 'PENDING' || value === 'ACCEPTED' || value === 'CANCELLED' || value === 'EXPIRED')
    return value;
  return 'EXPIRED';
}

function parseInviteRole(value: string): InviteRole {
  if (value === 'ADMIN' || value === 'MEMBER') return value;
  return 'MEMBER';
}

/**
 * Maps a DB row to InviteSummary (tokenHash excluded — safe for API responses).
 * Used by all admin query functions.
 */
export function rowToInviteSummary(row: {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  status: string;
  expires_at: Date;
  used_at: Date | null;
  created_at: Date;
  created_by_user_id: string | null;
}): InviteSummary {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    email: row.email,
    role: parseInviteRole(row.role),
    status: parseInviteStatus(row.status),
    expiresAt: row.expires_at,
    usedAt: row.used_at ?? null,
    createdAt: row.created_at,
    createdByUserId: row.created_by_user_id ?? null,
  };
}

export async function getInviteByTenantAndTokenHash(
  db: DbExecutor,
  params: { tenantId: string; tokenHash: string },
): Promise<Invite | undefined> {
  const row = await findInviteByTenantAndTokenHashSql(db, params);
  if (!row) return undefined;

  return {
    id: row.id,
    tenantId: row.tenant_id,

    email: row.email,
    role: parseInviteRole(row.role),
    status: parseInviteStatus(row.status),

    tokenHash: row.token_hash,

    expiresAt: row.expires_at,
    usedAt: row.used_at ?? null,

    createdAt: row.created_at,
    createdByUserId: row.created_by_user_id ?? null,
  };
}

/**
 * Returns the most-recently-created PENDING invite for (tenantId, email),
 * or undefined if none exists.
 *
 * Used by createInvite to detect duplicates before inserting a new row.
 */
export async function getPendingInviteByTenantAndEmail(
  db: DbExecutor,
  params: { tenantId: string; email: string },
): Promise<InviteSummary | undefined> {
  const row = await findPendingInviteByTenantAndEmailSql(db, params);
  if (!row) return undefined;
  return rowToInviteSummary(row);
}

/**
 * Returns the most-recently-created invite for (tenantId, email), regardless of
 * terminal status. Used by auth-entry policy resolution.
 */
export async function getLatestInviteByTenantAndEmail(
  db: DbExecutor,
  params: { tenantId: string; email: string },
): Promise<Invite | undefined> {
  const row = await findLatestInviteByTenantAndEmailSql(db, params);
  if (!row) return undefined;

  return {
    id: row.id,
    tenantId: row.tenant_id,
    email: row.email,
    role: parseInviteRole(row.role),
    status: parseInviteStatus(row.status),
    tokenHash: row.token_hash,
    expiresAt: row.expires_at,
    usedAt: row.used_at ?? null,
    createdAt: row.created_at,
    createdByUserId: row.created_by_user_id ?? null,
  };
}

/**
 * Loads a single invite by its ID, scoped to the given tenantId.
 * Returns undefined when not found OR when the invite belongs to a different tenant
 * (cross-tenant read returns the same undefined — no existence oracle).
 *
 * Used by resendInvite and cancelInvite inside their transaction boundaries.
 */
export async function getInviteByIdAndTenant(
  db: DbExecutor,
  params: { inviteId: string; tenantId: string },
): Promise<InviteSummary | undefined> {
  const row = await findInviteByIdAndTenantSql(db, params);
  if (!row) return undefined;
  return rowToInviteSummary(row);
}

/**
 * Returns a paginated slice of invites for a tenant plus the total count.
 * Optional status filter narrows results to a single status value.
 *
 * Used by the GET /admin/invites list endpoint.
 */
export async function listInvitesByTenant(
  db: DbExecutor,
  params: {
    tenantId: string;
    status?: InviteStatus;
    limit: number;
    offset: number;
  },
): Promise<{ invites: InviteSummary[]; total: number }> {
  const [rows, total] = await Promise.all([
    findInvitesByTenantSql(db, {
      tenantId: params.tenantId,
      status: params.status,
      limit: params.limit,
      offset: params.offset,
    }),
    countInvitesByTenantSql(db, {
      tenantId: params.tenantId,
      status: params.status,
    }),
  ]);

  return {
    invites: rows.map(rowToInviteSummary),
    total,
  };
}
