/**
 * src/modules/auth/helpers/create-auth-session.ts
 *
 * WHY:
 * - Shared orchestration for deciding nextAction and creating a session.
 *
 * STAGE 2:
 * - Persist emailVerified into the Redis session payload so admin guards can enforce it
 *   without additional DB reads.
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
  hasVerifiedMfaSecret: boolean;
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
    mfaVerified: nextAction === 'NONE',
    emailVerified: emailVerified ?? true,
    createdAt: now.toISOString(),
  });

  return { sessionId, nextAction };
}
