/**
 * src/modules/_shared/use-cases/provision-user-to-tenant.usecase.ts
 *
 * WHY:
 * - "Find-or-create user + create/activate membership" is not unique to registration.
 * - SSO (Brick 10) and public signup (Brick 11) need the exact same logic.
 * - Extracting here means SUSPENDED blocking, idempotency guards, and audit flags
 *   are defined once and tested once.
 *
 * WHAT IT DOES:
 * - Finds or creates a global User by email.
 * - Finds an existing Membership for (tenantId, userId):
 *   - SUSPENDED  → throws (caller decides the error)
 *   - INVITED    → activates → ACTIVE
 *   - ACTIVE     → no-op (idempotent)
 *   - not found  → creates as ACTIVE with the given role
 * - Returns result flags so the caller knows what audit events to emit.
 *
 * RULES:
 * - Receives trx-bound repos (caller owns the transaction).
 * - Does NOT start a transaction.
 * - Does NOT write audit events (caller owns audit context).
 * - Does NOT create auth identities (that is a separate responsibility).
 * - Throws MembershipErrors.membershipSuspended if membership is SUSPENDED.
 */

import { getUserByEmail } from '../../users/queries/user.queries';
import type { UserRepo } from '../../users/dal/user.repo';
import type { User } from '../../users/user.types';

import { getMembershipByTenantAndUser } from '../../memberships/membership.queries';
import type { MembershipRepo } from '../../memberships/dal/membership.repo';
import type { Membership, MembershipRole } from '../../memberships/membership.types';

import type { DbExecutor } from '../../../shared/db/db';
import { MembershipErrors } from '../../memberships/membership.errors';

// ── Input ────────────────────────────────────────────────────

export type ProvisionUserToTenantParams = {
  /** Transaction-bound db executor. */
  trx: DbExecutor;
  /** Transaction-bound user repo. */
  userRepo: UserRepo;
  /** Transaction-bound membership repo. */
  membershipRepo: MembershipRepo;
  /** Normalised (lowercase) email. */
  email: string;
  /** Display name — only used when creating a new user. */
  name: string | null;
  /** Target tenant. */
  tenantId: string;
  /**
   * Role assigned when a NEW membership is created.
   * If the membership already exists, the existing role is preserved.
   */
  role: MembershipRole;
  /** Used for acceptedAt / invitedAt timestamps. */
  now: Date;
};

// ── Output ───────────────────────────────────────────────────

export type ProvisionResult = {
  user: User;
  membership: Membership;
  /** True if the user row was inserted (vs. already existed). */
  userCreated: boolean;
  /** True if an existing INVITED membership was flipped to ACTIVE. */
  membershipActivated: boolean;
  /** True if a new membership row was inserted as ACTIVE. */
  membershipCreated: boolean;
};

// ── Use-case ─────────────────────────────────────────────────

export async function provisionUserToTenant(
  params: ProvisionUserToTenantParams,
): Promise<ProvisionResult> {
  const { trx, userRepo, membershipRepo, email, name, tenantId, role, now } = params;

  // ── 1. Find or create user ────────────────────────────────

  const existingUser = await getUserByEmail(trx, email);
  let userCreated = false;

  let user: User;

  if (existingUser) {
    user = existingUser;
  } else {
    const created = await userRepo.insertUser({ email, name });
    user = {
      id: created.id,
      email: created.email,
      name,
      createdAt: now,
      updatedAt: now,
    };
    userCreated = true;
  }

  // ── 2. Find or create/activate membership ─────────────────

  const existingMembership = await getMembershipByTenantAndUser(trx, {
    tenantId,
    userId: user.id,
  });

  let membershipActivated = false;
  let membershipCreated = false;
  let membership: Membership;

  if (existingMembership) {
    if (existingMembership.status === 'SUSPENDED') {
      throw MembershipErrors.membershipSuspended();
    }

    if (existingMembership.status === 'INVITED') {
      const activated = await membershipRepo.activateMembership({
        membershipId: existingMembership.id,
        acceptedAt: now,
      });

      membership = activated
        ? { ...existingMembership, status: 'ACTIVE', acceptedAt: now }
        : existingMembership;

      membershipActivated = !!activated;
    } else {
      // ACTIVE — idempotent, no action needed
      membership = existingMembership;
    }
  } else {
    const created = await membershipRepo.insertMembership({
      tenantId,
      userId: user.id,
      role,
      status: 'ACTIVE',
      invitedAt: now,
    });

    membership = {
      id: created.id,
      tenantId,
      userId: user.id,
      role,
      status: 'ACTIVE',
      invitedAt: now,
      acceptedAt: now,
      suspendedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    membershipCreated = true;
  }

  return { user, membership, userCreated, membershipActivated, membershipCreated };
}
