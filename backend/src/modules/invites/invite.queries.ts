/**
 * backend/src/modules/invites/invite.queries.ts
 *
 * WHY:
 * - Queries are read-only and side-effect free.
 * - They shape DB rows into Invites domain types.
 *
 * RULES:
 * - Read-only.
 * - Tenant-scoped when applicable.
 * - No AppError.
 */

import type { DbExecutor } from '../../shared/db/db';
import { findInviteByTenantAndTokenHashSql } from './dal/invite.query-sql';
import type { Invite, InviteRole, InviteStatus } from './invite.types';

function parseInviteStatus(value: string): InviteStatus {
  if (value === 'PENDING' || value === 'ACCEPTED' || value === 'CANCELLED' || value === 'EXPIRED')
    return value;
  return 'EXPIRED';
}

function parseInviteRole(value: string): InviteRole {
  if (value === 'ADMIN' || value === 'MEMBER') return value;
  return 'MEMBER';
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
