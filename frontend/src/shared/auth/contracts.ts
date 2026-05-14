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
 *   - backend/src/modules/invites/admin/admin-invite.controller.ts
 *   - backend/docs/api/auth.md
 * - Do not invent frontend-only auth state here.
 * - Prefer exact string unions over broad `string` where backend behavior is locked.
 *
 * 9/10 HARDENING:
 * - Added signupAllowed to ConfigResponse to match backend auth.types.ts.
 *   Frontend code must use signupAllowed (not publicSignupEnabled) to decide
 *   whether to render signup entry points. See backend auth.types.ts for rationale.
 *
 * LEGACY SCAFFOLD NOTE:
 * - setupCompleted remains in ConfigResponse.tenant as a compatibility field
 *   derived from the retired auth-phase acknowledgement timestamp.
 * - Current `/admin` and `/admin/settings` pages do not read this field for
 *   live Settings progress. They now use `GET /settings/bootstrap` and
 *   `GET /settings/overview` instead.
 *
 * ROLE COMPATIBILITY NOTE:
 * - Backend canonical runtime roles are ADMIN / AGENT / USER.
 * - MEMBER is accepted only as a legacy wire/input alias and is normalized to USER
 *   before route-state, session display, or auth result data reaches page code.
 * - Admin invite create requests now send only canonical ADMIN / AGENT / USER.
 * - Invite responses still normalize legacy MEMBER to USER defensively at the
 *   browser API boundary while the compatibility window exists.
 * - AGENT currently routes as authenticated non-admin workspace user; Operational
 *   Access is not implemented in this frontend contract.
 *
 * - AuthNextAction is NOT extended — workspace setup is tenant state, not auth
 *   continuation state. See ADR 0003 and the Settings bootstrap ADR.
 */

export type AuthProvider = 'password' | 'google' | 'microsoft';
export type PublicSsoProvider = Exclude<AuthProvider, 'password'>;
export type CanonicalMembershipRole = 'ADMIN' | 'AGENT' | 'USER';
export type LegacyMembershipRole = 'MEMBER';
export type MembershipRole = CanonicalMembershipRole;
export type MembershipRoleInput = MembershipRole | LegacyMembershipRole;
export type InviteRole = MembershipRole;
export type InviteRoleInput = InviteRole | LegacyMembershipRole;
export type InviteStatus = 'PENDING' | 'ACCEPTED' | 'CANCELLED' | 'EXPIRED';

export type AgentInviteGroupSummary = {
  id: string;
  name: string;
  level: 'ADMIN' | 'AGENT' | 'USER';
  status: 'ACTIVE' | 'ARCHIVED';
};

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

export type AuthMembershipWire = {
  id: string;
  role: MembershipRoleInput;
};

export type AuthResult = {
  status: AuthResultStatus;
  nextAction: AuthNextAction;
  user: AuthUser;
  membership: AuthMembership;
};

export type AuthResultWire = Omit<AuthResult, 'membership'> & {
  membership: AuthMembershipWire;
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

export type MeResponseWire = Omit<MeResponse, 'membership'> & {
  membership: AuthMembershipWire;
};

export type ConfigResponse = {
  tenant: {
    name: string;
    isActive: boolean;
    publicSignupEnabled: boolean;
    /**
     * Use this field — not publicSignupEnabled — to decide whether to show
     * signup UI. signupAllowed = publicSignupEnabled && !adminInviteRequired.
     * A tenant can have publicSignupEnabled=true but still block public signup
     * via adminInviteRequired=true. The backend returns the correct computed
     * value here so the frontend does not need to re-implement the rule.
     */
    signupAllowed: boolean;
    allowedSso: PublicSsoProvider[];
    /**
     * Legacy auth scaffold field. Derived from setup_completed_at and retained
     * for compatibility while the bridge remains in the backend. The current
     * `/admin` and `/admin/settings` pages no longer use this field for live
     * Settings progress.
     */
    setupCompleted: boolean;
  };
};

export type InviteSummary = {
  id: string;
  tenantId: string;
  email: string;
  role: InviteRole;
  status: InviteStatus;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
  createdByUserId: string | null;
  agentGroups?: AgentInviteGroupSummary[];
};

export type InviteSummaryWire = Omit<InviteSummary, 'role'> & {
  role: InviteRoleInput;
};

export type AcceptInviteRequest = {
  token: string;
};

export type AcceptInviteResponse = {
  status: 'ACCEPTED';
  nextAction: InviteAcceptNextAction;
  email: string;
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

export type CreateAdminInviteRequest = {
  email: string;
  role: InviteRole;
  agentGroupIds?: string[];
};

export type CreateAdminInviteResponse = {
  invite: InviteSummary;
};

export type CreateAdminInviteResponseWire = {
  invite: InviteSummaryWire;
};

export type ListAdminInvitesRequest = {
  limit?: number;
  offset?: number;
  status?: InviteStatus;
};

export type ListAdminInvitesResponse = {
  invites: InviteSummary[];
  total: number;
  limit: number;
  offset: number;
};

export type ListAdminInvitesResponseWire = Omit<ListAdminInvitesResponse, 'invites'> & {
  invites: InviteSummaryWire[];
};

export type ResendAdminInviteResponse = {
  invite: InviteSummary;
};

export type ResendAdminInviteResponseWire = {
  invite: InviteSummaryWire;
};

export type CancelAdminInviteResponse = {
  status: 'CANCELLED';
};

export type BackendErrorResponse = {
  error: {
    code: string;
    message: string;
  };
};

export function normalizeMembershipRole(role: MembershipRoleInput): MembershipRole {
  return role === 'MEMBER' ? 'USER' : role;
}

export function normalizeAuthMembership(membership: AuthMembershipWire): AuthMembership {
  return {
    ...membership,
    role: normalizeMembershipRole(membership.role),
  };
}

export function normalizeAuthResult(result: AuthResultWire): AuthResult {
  return {
    ...result,
    membership: normalizeAuthMembership(result.membership),
  };
}

export function normalizeMeResponse(response: MeResponseWire): MeResponse {
  return {
    ...response,
    membership: normalizeAuthMembership(response.membership),
  };
}

export function normalizeInviteSummary(invite: InviteSummaryWire): InviteSummary {
  return {
    ...invite,
    role: normalizeMembershipRole(invite.role),
  };
}

export function normalizeCreateAdminInviteResponse(
  response: CreateAdminInviteResponseWire,
): CreateAdminInviteResponse {
  return {
    invite: normalizeInviteSummary(response.invite),
  };
}

export function normalizeListAdminInvitesResponse(
  response: ListAdminInvitesResponseWire,
): ListAdminInvitesResponse {
  return {
    ...response,
    invites: response.invites.map(normalizeInviteSummary),
  };
}

export function normalizeResendAdminInviteResponse(
  response: ResendAdminInviteResponseWire,
): ResendAdminInviteResponse {
  return {
    invite: normalizeInviteSummary(response.invite),
  };
}
