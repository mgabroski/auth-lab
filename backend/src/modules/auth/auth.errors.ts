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
 *
 * BRICK 11 UPDATE:
 * - Added public signup errors: signupDisabled, emailAlreadyMember,
 *   emailInvitePending, verificationTokenInvalid.
 *
 * PHASE 1B UPDATE:
 * - Added invitationExpired so runtime auth flows can keep expired invited-entry
 *   state distinct from valid invited-entry state.
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

  inviteNotYetAccepted(meta?: AppErrorMeta) {
    return AppError.forbidden('Please accept your invite before signing in.', meta);
  },

  /** No membership for this tenant. */
  noAccess(meta?: AppErrorMeta) {
    return AppError.forbidden("You don't have access to this workspace.", meta);
  },

  /**
   * Password reset token is invalid, expired, or already used.
   *
   * SECURITY: A single error covers all three conditions intentionally.
   */
  resetTokenInvalid(meta?: AppErrorMeta) {
    return AppError.validationError(
      'This password reset link is invalid or has expired. Please request a new one.',
      meta,
    );
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // SSO (Brick 10)
  // ─────────────────────────────────────────────────────────────────────────────

  ssoSubjectDrift(meta?: AppErrorMeta) {
    return AppError.forbidden('SSO identity mismatch. Contact your admin.', meta);
  },

  ssoEmailNotVerified(meta?: AppErrorMeta) {
    return AppError.forbidden('Your Google account email is not verified.', meta);
  },

  ssoProviderNotAllowed(meta?: AppErrorMeta) {
    return AppError.forbidden('This sign-in method is not enabled for this workspace.', meta);
  },

  ssoStateInvalid(meta?: AppErrorMeta) {
    return AppError.validationError('Invalid or expired SSO request. Please try again.', meta);
  },

  ssoTokenValidationFailed(meta?: AppErrorMeta) {
    return AppError.unauthorized('SSO token validation failed.', meta);
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // Public Signup (Brick 11)
  // ─────────────────────────────────────────────────────────────────────────────

  /** Tenant has public_signup_enabled = false. */
  signupDisabled(meta?: AppErrorMeta) {
    return AppError.forbidden('Sign up is disabled. You need an invitation to join.', meta);
  },

  /**
   * User already has an ACTIVE membership in this tenant.
   * Tells them to sign in rather than revealing membership details.
   */
  emailAlreadyMember(meta?: AppErrorMeta) {
    return AppError.conflict('Already a member. Please sign in.', meta);
  },

  /**
   * User has a PENDING/INVITED membership in this tenant.
   * Direct them to the invite email.
   */
  emailInvitePending(meta?: AppErrorMeta) {
    return AppError.conflict('You have a pending invitation. Please check your email.', meta);
  },

  /**
   * The workspace has invite-only state for this email, but the invite is no
   * longer usable because it expired. Kept distinct from emailInvitePending.
   */
  invitationExpired(meta?: AppErrorMeta) {
    return AppError.conflict('This invitation link has expired. Contact your admin.', meta);
  },

  /**
   * Email verification token is invalid, expired, or already used.
   *
   * SECURITY: A single error covers all three conditions — same rationale as
   * resetTokenInvalid. Separate errors would create an oracle.
   */
  verificationTokenInvalid(meta?: AppErrorMeta) {
    return AppError.validationError(
      'This verification link is invalid or has expired. Request a new one.',
      meta,
    );
  },
} as const;
