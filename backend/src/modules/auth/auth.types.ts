/**
 * src/modules/auth/auth.types.ts
 *
 * WHY:
 * - Domain types for the Auth module.
 * - AuthIdentity represents a login method for a user (password, google, microsoft).
 * - Response types define what register/login endpoints return.
 * - PasswordResetToken represents an active reset token (used_at IS NULL).
 *
 * RULES:
 * - Keep aligned with DB schema.
 * - Never include raw passwords, hashes, or tokens in response types.
 */

export type AuthProvider = 'password' | 'google' | 'microsoft';

export type AuthIdentity = {
  id: string;
  userId: string;
  provider: AuthProvider;
  providerSubject: string | null;
  // passwordHash intentionally excluded from domain type
  createdAt: Date;
  updatedAt: Date;
};

/**
 * Represents a valid (not-yet-used, not-expired) password reset token.
 * The raw token is never stored here — only the hash lives in the DB.
 */
export type PasswordResetToken = {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  createdAt: Date;
};

/**
 * MFA next-action tells the client what to do after register/login.
 * - NONE: fully authenticated, no MFA needed
 * - MFA_SETUP_REQUIRED: admin who hasn't set up MFA yet
 * - MFA_REQUIRED: admin (or member if tenant requires) must verify MFA
 */
export type MfaNextAction = 'NONE' | 'MFA_SETUP_REQUIRED' | 'MFA_REQUIRED';

export type AuthResult = {
  status: 'AUTHENTICATED';
  nextAction: MfaNextAction;
  user: {
    id: string;
    email: string;
    name: string | null;
  };
  membership: {
    id: string;
    role: 'ADMIN' | 'MEMBER';
  };
};
