/**
 * src/modules/auth/helpers/build-auth-result.ts
 *
 * WHY:
 * - The AuthResult response shape is constructed identically in register()
 *   and login(). Without this helper it will also be duplicated by SSO (Brick 10).
 * - Fixes a type coercion bug in the original service: `name: user.name ?? ''`
 *   silently coerces null to empty string, contradicting AuthResult's declared
 *   type of `name: string | null`.
 *
 * RULES:
 * - Pure function. No I/O.
 * - Passes null through for name — never coerces to empty string.
 */

import type { AuthResult, MfaNextAction } from '../auth.types';
import type { User } from '../../users/user.types';
import type { Membership } from '../../memberships/membership.types';

export type BuildAuthResultParams = {
  nextAction: MfaNextAction;
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
