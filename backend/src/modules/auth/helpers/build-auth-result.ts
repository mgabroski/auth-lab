/**
 * src/modules/auth/helpers/build-auth-result.ts
 *
 * WHY:
 * - The AuthResult response shape is constructed identically in register(),
 *   login(), SSO, and signup. Without this helper it would be duplicated.
 * - Fixes a type coercion bug in the original service: `name: user.name ?? ''`
 *   silently coerces null to empty string, contradicting AuthResult's declared
 *   type of `name: string | null`.
 *
 * RULES:
 * - Pure function. No I/O.
 * - Passes null through for name — never coerces to empty string.
 *
 * BRICK 11 UPDATE:
 * - Updated nextAction type from MfaNextAction to AuthNextAction (superset).
 */

import type { AuthResult, AuthNextAction } from '../auth.types';
import type { User } from '../../users/user.types';
import type { Membership } from '../../memberships/membership.types';

export type BuildAuthResultParams = {
  nextAction: AuthNextAction;
  user: Pick<User, 'id' | 'email' | 'name'>;
  membership: Pick<Membership, 'id' | 'role'>;
};

export function buildAuthResult(params: BuildAuthResultParams): AuthResult {
  const { nextAction, user, membership } = params;

  return {
    status: 'AUTHENTICATED',
    nextAction,
    user: {
      id: user.id,
      email: user.email,
      name: user.name ?? null,
    },
    membership: {
      id: membership.id,
      role: membership.role,
    },
  };
}
