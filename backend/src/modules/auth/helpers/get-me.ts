/**
 * src/modules/auth/helpers/get-me.ts
 *
 * WHY:
 * - Owns all read-side logic for GET /auth/me.
 * - Keeps AuthService thin and AuthController free of DB reads.
 * - Centralizes nextAction derivation for frontend bootstrap.
 *
 * RULES:
 * - No HTTP concerns here.
 * - DB reads only; no writes.
 * - Final nextAction decision must route through decideLoginNextAction.
 * - User + tenant reads must execute in Promise.all.
 *
 * Note (Phase 9): workspace setup state is NOT derived here.
 * setupCompleted lives in GET /auth/config (ConfigResponse) and is read
 * separately by the frontend bootstrap. AuthNextAction is not extended
 * with setup state — see ADR 0003.
 */

import { AppError } from '../../../shared/http/errors';
import type { RequiredAuthContext } from '../../../shared/http/require-auth-context';
import type { DbExecutor } from '../../../shared/db/db';
import { getUserById } from '../../users/queries/user.queries';
import { getTenantById } from '../../tenants/queries/tenant.queries';
import { hasVerifiedMfaSecret } from './has-verified-mfa-secret';
import { isMfaRequiredForLogin } from '../policies/mfa-required.policy';
import { decideLoginNextAction } from '../policies/login-next-action.policy';
import type { MeResponse, AuthNextAction } from '../auth.types';

export async function getMe(auth: RequiredAuthContext, db: DbExecutor): Promise<MeResponse> {
  const [user, tenant] = await Promise.all([
    getUserById(db, auth.userId),
    getTenantById(db, auth.tenantId),
  ]);

  if (!user || !tenant) {
    throw AppError.internal();
  }

  let nextAction: AuthNextAction;

  if (!auth.emailVerified) {
    nextAction = 'EMAIL_VERIFICATION_REQUIRED';
  } else if (auth.mfaVerified) {
    nextAction = 'NONE';
  } else {
    const mfaRequired = isMfaRequiredForLogin({
      role: auth.role,
      tenantMemberMfaRequired: tenant.memberMfaRequired,
    });

    const hasVerifiedSecret = mfaRequired ? await hasVerifiedMfaSecret(db, auth.userId) : false;

    nextAction = decideLoginNextAction({
      role: auth.role,
      memberMfaRequired: tenant.memberMfaRequired,
      hasVerifiedMfaSecret: hasVerifiedSecret,
      emailVerified: true,
    });
  }

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
    },
    membership: {
      id: auth.membershipId,
      role: auth.role,
    },
    tenant: {
      id: tenant.id,
      key: tenant.key,
      name: tenant.name,
    },
    session: {
      mfaVerified: auth.mfaVerified,
      emailVerified: auth.emailVerified,
    },
    nextAction,
  };
}
