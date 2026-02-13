/**
 * src/modules/auth/auth.errors.ts
 *
 * WHY:
 * - Auth module owns its domain-specific error semantics.
 * - Security-safe: error messages never reveal whether an email exists.
 *
 * RULES:
 * - Use AppError as the transport primitive.
 * - Never include passwords, tokens, or hashes in meta.
 */

import { AppError, type AppErrorMeta } from '../../shared/http/errors';

export const AuthErrors = {
  /** Login: wrong email or password. Intentionally vague. */
  invalidCredentials(meta?: AppErrorMeta) {
    return AppError.unauthorized('Invalid email or password.', meta);
  },

  /** Registration: password auth_identity already exists for this user. */
  alreadyRegistered(meta?: AppErrorMeta) {
    return AppError.conflict('This email is already registered. Please sign in.', meta);
  },

  /** Invite not in ACCEPTED state (not yet accepted or already consumed). */
  inviteNotAccepted(meta?: AppErrorMeta) {
    return AppError.conflict('This invite has not been accepted or has already been used.', meta);
  },

  /** Email in request doesn't match invite email. */
  emailMismatch(meta?: AppErrorMeta) {
    return AppError.validationError('Email does not match the invite.', meta);
  },

  /** User has SSO identity but no password — tried password login. */
  ssoOnlyUser(meta?: AppErrorMeta) {
    return AppError.conflict('Please sign in with your SSO provider (Google/Microsoft).', meta);
  },

  /** Account suspended. */
  accountSuspended(meta?: AppErrorMeta) {
    return AppError.forbidden('Your account has been suspended.', meta);
  },

  /** Membership is INVITED — user needs to accept invite first. */
  inviteNotYetAccepted(meta?: AppErrorMeta) {
    return AppError.conflict('Please accept your invite before signing in.', meta);
  },

  /** No membership for this tenant. */
  noAccess(meta?: AppErrorMeta) {
    return AppError.forbidden("You don't have access to this workspace.", meta);
  },

  /**
   * Password reset token is invalid, expired, or already used.
   *
   * SECURITY: A single error covers all three conditions intentionally.
   * Separate errors (token_not_found vs token_expired vs token_used) would
   * let an attacker determine whether a token exists in the system, whether
   * it was recently consumed, or whether it was ever issued — providing an
   * oracle that could aid targeted attacks.
   */
  resetTokenInvalid(meta?: AppErrorMeta) {
    return AppError.validationError(
      'This password reset link is invalid or has expired. Please request a new one.',
      meta,
    );
  },
} as const;
