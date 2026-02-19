/**
 * src/modules/auth/helpers/create-auth-session.ts
 *
 * WHY:
 * - The sequence (decideLoginNextAction → sessionStore.create → return result)
 *   is identical in register() and login(), and will repeat in SSO (Brick 10).
 * - MFA nextAction is a pure policy decision; session creation is infra orchestration.
 *
 * RULES:
 * - No DB access (sessions live in Redis via SessionStore).
 * - No business rules beyond MFA determination.
 * - isProduction is NOT needed here — cookie flags are set by the controller.
 */

import type { SessionStore } from '../../../shared/session/session.store';
import type { MfaNextAction } from '../auth.types';
import type { Tenant } from '../../tenants/tenant.types';
import { decideLoginNextAction } from '../policies/login-next-action.policy';

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

  // Shared policy: MFA decision is identical for login/register.
  const nextAction: MfaNextAction = decideLoginNextAction({
    role,
    memberMfaRequired: tenant.memberMfaRequired,
    hasVerifiedMfaSecret,
  });

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
