/**
 * frontend/src/shared/auth/contracts.ts
 *
 * WHY:
 * - Central frontend contract layer for the backend Auth + invite provisioning modules.
 * - Keeps route/page code grounded in actual backend request/response shapes.
 * - Prevents ad-hoc inline DTOs from drifting across the frontend.
 *
 * RULES:
 * - These types must mirror the current backend truth from:
 *   - backend/src/modules/auth/auth.types.ts
 *   - backend/src/modules/invites/flows/execute-accept-invite-flow.ts
 *   - backend/docs/api/auth.md
 * - Do not invent frontend-only auth state here.
 * - Prefer exact string unions over broad `string` where backend behavior is locked.
 */

export type AuthProvider = 'password' | 'google' | 'microsoft';
export type PublicSsoProvider = Exclude<AuthProvider, 'password'>;
export type MembershipRole = 'ADMIN' | 'MEMBER';

export type AuthNextAction =
  | 'NONE'
  | 'MFA_SETUP_REQUIRED'
  | 'MFA_REQUIRED'
  | 'EMAIL_VERIFICATION_REQUIRED';

export type InviteAcceptNextAction = 'SET_PASSWORD' | 'SIGN_IN' | 'MFA_SETUP_REQUIRED';

export type AuthResultStatus = 'AUTHENTICATED' | 'EMAIL_VERIFICATION_REQUIRED';

export type AuthUser = {
  id: string;
  email: string;
  name: string | null;
};

export type AuthMembership = {
  id: string;
  role: MembershipRole;
};

export type AuthResult = {
  status: AuthResultStatus;
  nextAction: AuthNextAction;
  user: AuthUser;
  membership: AuthMembership;
};

export type MeResponse = {
  user: AuthUser;
  membership: AuthMembership;
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

export type ConfigResponse = {
  tenant: {
    name: string;
    isActive: boolean;
    publicSignupEnabled: boolean;
    allowedSso: PublicSsoProvider[];
  };
};

export type AcceptInviteRequest = {
  token: string;
};

export type AcceptInviteResponse = {
  status: 'ACCEPTED';
  nextAction: InviteAcceptNextAction;
};

export type RegisterRequest = {
  email: string;
  password: string;
  name: string;
  inviteToken: string;
};

export type LoginRequest = {
  email: string;
  password: string;
};

export type SignupRequest = {
  email: string;
  password: string;
  name: string;
};

export type ForgotPasswordRequest = {
  email: string;
};

export type ForgotPasswordResponse = {
  message: 'If an account with that email exists, a password reset link has been sent.';
};

export type ResetPasswordRequest = {
  token: string;
  newPassword: string;
};

export type ResetPasswordResponse = {
  message: 'Password updated successfully. Please sign in with your new password.';
};

export type VerifyEmailRequest = {
  token: string;
};

export type VerifyEmailResponse = {
  status: 'VERIFIED';
};

export type ResendVerificationResponse = {
  message: 'If your email is unverified, a new verification link has been sent.';
};

export type MfaSetupResponse = {
  secret: string;
  qrCodeUri: string;
  recoveryCodes: string[];
};

export type MfaCodeRequest = {
  code: string;
};

export type MfaRecoverRequest = {
  recoveryCode: string;
};

export type MfaVerifyResponse = {
  status: 'AUTHENTICATED';
  nextAction: 'NONE';
};

export type LogoutResponse = {
  message: 'Logged out.';
};

export type BackendErrorResponse = {
  error: {
    code: string;
    message: string;
  };
};
