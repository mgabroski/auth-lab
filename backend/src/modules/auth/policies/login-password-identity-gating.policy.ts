/**
 * WHY:
 * - Login requires a password identity for password-based auth.
 * - Keep rule pure + unit-testable.
 *
 * RULE:
 * - If password identity is missing → invalid credentials (anti-enumeration).
 */

import { AuthErrors } from '../auth.errors';

export type PasswordIdentityLike = Readonly<{
  passwordHash: string;
}>;

export type PasswordGatingFailure = {
  reason: 'no_password_identity';
  error: Error;
};

export function getLoginPasswordIdentityFailure(
  identity: PasswordIdentityLike | null | undefined,
): PasswordGatingFailure | null {
  if (!identity) {
    return { reason: 'no_password_identity', error: AuthErrors.invalidCredentials() };
  }
  return null;
}

export function assertLoginPasswordIdentityAllowed(
  identity: PasswordIdentityLike | null | undefined,
): asserts identity is PasswordIdentityLike {
  const failure = getLoginPasswordIdentityFailure(identity);
  if (failure) throw failure.error;
}
