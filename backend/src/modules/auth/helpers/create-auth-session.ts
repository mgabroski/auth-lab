/**
 * src/modules/auth/helpers/create-auth-session.ts
 *
 * WHY:
 * - The sequence (determineMfaNextAction → sessionStore.create → return result)
 *   is identical in register() and login(), and will repeat in SSO (Brick 10).
 * - determineMfaNextAction is exported separately so it can be unit-tested
 *   without a real SessionStore.
 *
 * RULES:
 * - No DB access (sessions live in Redis via SessionStore).
 * - No business rules beyond MFA determination.
 * - isProduction is NOT needed here — cookie flags are set by the controller.
 */

import type { SessionStore } from '../../../shared/session/session.store';
import type { MfaNextAction } from '../auth.types';
import type { Tenant } from '../../tenants/tenant.types';

// ── MFA determination ─────────────────────────────────────────

/**
 * Determines what MFA action the client must take after authentication.
 *
 * Brick 9 rules:
 * - Admins: MFA is mandatory. If configured => MFA_REQUIRED; else => MFA_SETUP_REQUIRED.
 * - Members: MFA is required if tenant.memberMfaRequired = true (same logic).
 * - If MFA is not required => NONE.
 */
export function determineMfaNextAction(
  role: 'ADMIN' | 'MEMBER',
  tenant: Tenant,
  hasVerifiedMfaSecret: boolean,
): MfaNextAction {
  const mfaRequired = role === 'ADMIN' || tenant.memberMfaRequired;

  if (!mfaRequired) return 'NONE';

  return hasVerifiedMfaSecret ? 'MFA_REQUIRED' : 'MFA_SETUP_REQUIRED';
}

// ── Session creation ──────────────────────────────────────────

export type CreateAuthSessionParams = {
  sessionStore: SessionStore;
  userId: string;
  tenantId: string;
  tenantKey: string;
  membershipId: string;
  role: 'ADMIN' | 'MEMBER';
  tenant: Tenant;

  /**
   * Computed by the service (DB read) before session creation.
   * We keep DB out of this helper.
   */
  hasVerifiedMfaSecret: boolean;

  now: Date;
};

export type CreateAuthSessionResult = {
  sessionId: string;
  nextAction: MfaNextAction;
};

export async function createAuthSession(
  params: CreateAuthSessionParams,
): Promise<CreateAuthSessionResult> {
  const {
    sessionStore,
    userId,
    tenantId,
    tenantKey,
    membershipId,
    role,
    tenant,
    hasVerifiedMfaSecret,
    now,
  } = params;

  const nextAction = determineMfaNextAction(role, tenant, hasVerifiedMfaSecret);

  const sessionId = await sessionStore.create({
    userId,
    tenantId,
    tenantKey,
    membershipId,
    role,
    mfaVerified: nextAction === 'NONE',
    createdAt: now.toISOString(),
  });

  return { sessionId, nextAction };
}
