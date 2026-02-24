/**
 * src/modules/auth/helpers/create-auth-session.ts
 *
 * WHY:
 * - The sequence (decideLoginNextAction → sessionStore.create → return result)
 *   is identical in register(), login(), SSO, and signup. Without this helper
 *   it would be duplicated across every flow.
 * - MFA nextAction is a pure policy decision; session creation is infra orchestration.
 *
 * RULES:
 * - No DB access (sessions live in Redis via SessionStore).
 * - No business rules beyond MFA determination.
 * - isProduction is NOT needed here — cookie flags are set by the controller.
 *
 * BRICK 11 UPDATE:
 * - Added optional emailVerified param (Decision 3).
 * - Forwarded to decideLoginNextAction so that email_verified = false sets
 *   mfaVerified = false in the session (nextAction === 'NONE' gate).
 * - Return type updated to AuthNextAction (superset of MfaNextAction).
 * - All existing callers that omit emailVerified get DB default (true) behavior —
 *   zero behavior change.
 */

import type { SessionStore } from '../../../shared/session/session.store';
import type { AuthNextAction } from '../auth.types';
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

  /**
   * Decision 3 (Brick 11): when false, nextAction becomes
   * EMAIL_VERIFICATION_REQUIRED and mfaVerified is set to false in the session.
   * Omit (undefined) for all existing flows — DB default (true) applies.
   */
  emailVerified?: boolean;

  now: Date;
};

export type CreateAuthSessionResult = {
  sessionId: string;
  nextAction: AuthNextAction;
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
    emailVerified,
    now,
  } = params;

  // Shared policy: nextAction is identical for login/register/signup.
  // emailVerified defaults to true (omitted by existing callers).
  const nextAction: AuthNextAction = decideLoginNextAction({
    role,
    memberMfaRequired: tenant.memberMfaRequired,
    hasVerifiedMfaSecret,
    emailVerified,
  });

  const sessionId = await sessionStore.create({
    userId,
    tenantId,
    tenantKey,
    membershipId,
    role,
    // mfaVerified is false for any non-NONE nextAction (email not verified, MFA not verified, etc.)
    mfaVerified: nextAction === 'NONE',
    createdAt: now.toISOString(),
  });

  return { sessionId, nextAction };
}
