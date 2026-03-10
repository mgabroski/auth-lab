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
 *
 * BRICK 11 UPDATE:
 * - MfaNextAction renamed to AuthNextAction (broader: covers email + MFA).
 * - Added 'EMAIL_VERIFICATION_REQUIRED' to AuthNextAction (Decision 3).
 * - MfaNextAction kept as a type alias for backward compatibility during the
 *   transition — remove once all callers have migrated.
 * - Added EmailVerificationToken domain type.
 *
 * STAGE 1 UPDATE:
 * - Added MeResponse for GET /auth/me.
 * - Added ConfigResponse for GET /auth/config.
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
 * Represents a valid (not-yet-used, not-expired) email verification token.
 * The raw token is never stored — only the hash lives in DB.
 */
export type EmailVerificationToken = {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  createdAt: Date;
};

/**
 * What the client should do after authenticate/register/signup.
 *
 * Precedence (Decision 3, Brick 11 — locked):
 *   EMAIL_VERIFICATION_REQUIRED  — always wins when email is unverified
 *   MFA_SETUP_REQUIRED           — admin who hasn't set up MFA yet
 *   MFA_REQUIRED                 — admin/member must verify MFA
 *   NONE                         — fully authenticated
 */
export type AuthNextAction =
  | 'NONE'
  | 'MFA_SETUP_REQUIRED'
  | 'MFA_REQUIRED'
  | 'EMAIL_VERIFICATION_REQUIRED';

/**
 * @deprecated Use AuthNextAction. Kept as alias for callers that have not yet
 * migrated. Will be removed in a follow-up cleanup.
 */
export type MfaNextAction = AuthNextAction;

export type AuthResult = {
  // FIX: signup can legitimately return EMAIL_VERIFICATION_REQUIRED
  status: 'AUTHENTICATED' | 'EMAIL_VERIFICATION_REQUIRED';
  nextAction: AuthNextAction;
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

/**
 * Response shape for GET /auth/me.
 * All fields are derived from session data + minimal DB reads (user name/email, tenant name).
 * Never contains raw secrets or tokens.
 */
export type MeResponse = {
  user: {
    id: string;
    email: string;
    name: string | null;
  };
  membership: {
    id: string;
    role: 'ADMIN' | 'MEMBER';
  };
  tenant: {
    id: string;
    key: string;
    name: string;
  };
  session: {
    mfaVerified: boolean;
    emailVerified: boolean;
  };
  nextAction: AuthNextAction;
};

/**
 * Response shape for GET /auth/config.
 * Public-safe only. Never contains allowedEmailDomains or memberMfaRequired.
 */
export type ConfigResponse = {
  tenant: {
    name: string;
    isActive: boolean;
    publicSignupEnabled: boolean;
    allowedSso: ('google' | 'microsoft')[];
  };
};

export type SsoIdentity = {
  id: string;
  userId: string;
  provider: 'google' | 'microsoft';
  providerSubject: string;
  createdAt: Date;
};
