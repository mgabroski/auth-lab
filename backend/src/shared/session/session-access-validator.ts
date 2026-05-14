/**
 * backend/src/shared/session/session-access-validator.ts
 *
 * WHY:
 * - Redis session payloads are deliberately small and fast to read, but tenant
 *   and membership access can change after the session is created.
 * - This validator is the fail-closed bridge between cached session identity
 *   and current database access truth.
 *
 * RULES:
 * - No AppError / HTTP concerns here. Return true/false only.
 * - Validate current tenant + membership state on every authenticated request.
 * - Normalize legacy role values before comparing cached session truth to DB truth.
 */

import type { DbExecutor } from '../db/db';
import { parseMembershipRole } from '../../modules/memberships/membership-role';
import type { SessionData } from './session.types';

export type SessionAccessValidator = {
  isSessionStillAllowed(session: SessionData): Promise<boolean>;
};

export class DatabaseSessionAccessValidator implements SessionAccessValidator {
  constructor(private readonly db: DbExecutor) {}

  async isSessionStillAllowed(session: SessionData): Promise<boolean> {
    const row = await this.db
      .selectFrom('memberships')
      .innerJoin('tenants', 'tenants.id', 'memberships.tenant_id')
      .select([
        'memberships.id as membership_id',
        'memberships.user_id as user_id',
        'memberships.tenant_id as tenant_id',
        'memberships.role as role',
        'memberships.status as membership_status',
        'tenants.key as tenant_key',
        'tenants.is_active as tenant_is_active',
      ])
      .where('memberships.id', '=', session.membershipId)
      .executeTakeFirst();

    if (!row) return false;

    const currentRole = parseMembershipRole(row.role);
    const sessionRole = parseMembershipRole(session.role);
    if (!currentRole || !sessionRole) return false;

    return (
      row.tenant_is_active === true &&
      row.membership_status === 'ACTIVE' &&
      row.membership_id === session.membershipId &&
      row.user_id === session.userId &&
      row.tenant_id === session.tenantId &&
      row.tenant_key === session.tenantKey &&
      currentRole === sessionRole
    );
  }
}
