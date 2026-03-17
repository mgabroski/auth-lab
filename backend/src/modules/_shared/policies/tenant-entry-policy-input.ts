/**
 * backend/src/modules/_shared/policies/tenant-entry-policy-input.ts
 *
 * WHY:
 * - Phase 1A needs one stable, explicit policy-input shape for all tenant entry
 *   decisions without changing live enforcement yet.
 * - Later phases (password signup, SSO, invite acceptance, registration,
 *   continuation routing) need the same normalized inputs instead of each flow
 *   ad-hoc interpreting tenant + invite + membership state.
 *
 * RULES:
 * - Pure only: no DB, no HTTP, no side effects.
 * - Preserve state detail instead of silently deciding policy.
 * - Normalize invite + membership state so callers can apply the locked
 *   expired-invite semantics consistently across signup and SSO paths.
 *
 * DESIGN NOTES:
 * - Current Auth-Lab behavior does NOT pre-create memberships on admin invite.
 *   A valid invite can therefore exist with no membership row yet.
 * - The normalized shape also supports a future INVITED membership row so later
 *   phases can reason over both models without changing the policy contract.
 */

import type { Invite, InviteRole, InviteStatus } from '../../invites/invite.types';
import type {
  Membership,
  MembershipRole,
  MembershipStatus,
} from '../../memberships/membership.types';
import type {
  Tenant,
  TenantAllowedEmailDomains,
  TenantAllowedSso,
  TenantKey,
} from '../../tenants/tenant.types';

export type NormalizedMembershipState = 'NONE' | MembershipStatus;
export type NormalizedInviteState = 'NONE' | 'VALID' | 'EXPIRED' | 'ONE_TIME_USED' | 'CANCELLED';
export type TenantEntryState = 'NONE' | 'INVITED' | 'ACTIVE' | 'SUSPENDED';
export type TenantEntryActivationState = 'NONE' | 'PENDING' | 'ACTIVE';

export type TenantPolicyInput = {
  id: string;
  key: TenantKey;
  isActive: boolean;
  publicSignupEnabled: boolean;
  adminInviteRequired: boolean;
  memberMfaRequired: boolean;
  allowedEmailDomains: TenantAllowedEmailDomains;
  allowedSso: TenantAllowedSso;
};

export type MembershipPolicyInput = {
  id: string | null;
  role: MembershipRole | null;
  state: NormalizedMembershipState;
  invitedAt: Date | null;
  acceptedAt: Date | null;
  suspendedAt: Date | null;
};

export type InvitePolicyInput = {
  id: string | null;
  email: string | null;
  role: InviteRole | null;
  rawStatus: InviteStatus | null;
  state: NormalizedInviteState;
  createdAt: Date | null;
  expiresAt: Date | null;
  consumedAt: Date | null;
};

export type TenantEntryPolicyInput = {
  tenant: TenantPolicyInput;
  membership: MembershipPolicyInput;
  invite: InvitePolicyInput;
  entry: {
    state: TenantEntryState;
    activationState: TenantEntryActivationState;
    canActivateLater: boolean;
  };
};

function normalizeMembershipState(membership?: Membership): NormalizedMembershipState {
  if (!membership) return 'NONE';
  return membership.status;
}

function normalizeInviteState(invite: Invite | undefined, now: Date): NormalizedInviteState {
  if (!invite) return 'NONE';

  if (invite.status === 'CANCELLED') return 'CANCELLED';
  if (invite.status === 'ACCEPTED') return 'ONE_TIME_USED';
  if (invite.status === 'EXPIRED') return 'EXPIRED';
  if (invite.expiresAt.getTime() <= now.getTime()) return 'EXPIRED';

  return 'VALID';
}

function deriveEntryState(params: {
  membershipState: NormalizedMembershipState;
  inviteState: NormalizedInviteState;
}): TenantEntryState {
  if (params.membershipState === 'ACTIVE') return 'ACTIVE';
  if (params.membershipState === 'SUSPENDED') return 'SUSPENDED';
  if (
    params.membershipState === 'INVITED' ||
    params.inviteState === 'VALID' ||
    params.inviteState === 'EXPIRED' ||
    params.inviteState === 'ONE_TIME_USED'
  ) {
    return 'INVITED';
  }
  return 'NONE';
}

function deriveActivationState(params: {
  membershipState: NormalizedMembershipState;
  inviteState: NormalizedInviteState;
}): TenantEntryActivationState {
  if (params.membershipState === 'ACTIVE') return 'ACTIVE';
  if (params.membershipState === 'INVITED') return 'PENDING';
  if (params.inviteState === 'ONE_TIME_USED') return 'PENDING';
  return 'NONE';
}

export function buildTenantEntryPolicyInput(params: {
  tenant: Tenant;
  membership?: Membership;
  invite?: Invite;
  now?: Date;
}): TenantEntryPolicyInput {
  const now = params.now ?? new Date();
  const membershipState = normalizeMembershipState(params.membership);
  const inviteState = normalizeInviteState(params.invite, now);
  const activationState = deriveActivationState({ membershipState, inviteState });

  return {
    tenant: {
      id: params.tenant.id,
      key: params.tenant.key,
      isActive: params.tenant.isActive,
      publicSignupEnabled: params.tenant.publicSignupEnabled,
      adminInviteRequired: params.tenant.adminInviteRequired,
      memberMfaRequired: params.tenant.memberMfaRequired,
      allowedEmailDomains: [...params.tenant.allowedEmailDomains],
      allowedSso: [...params.tenant.allowedSso],
    },
    membership: {
      id: params.membership?.id ?? null,
      role: params.membership?.role ?? null,
      state: membershipState,
      invitedAt: params.membership?.invitedAt ?? null,
      acceptedAt: params.membership?.acceptedAt ?? null,
      suspendedAt: params.membership?.suspendedAt ?? null,
    },
    invite: {
      id: params.invite?.id ?? null,
      email: params.invite?.email ?? null,
      role: params.invite?.role ?? null,
      rawStatus: params.invite?.status ?? null,
      state: inviteState,
      createdAt: params.invite?.createdAt ?? null,
      expiresAt: params.invite?.expiresAt ?? null,
      consumedAt: params.invite?.usedAt ?? null,
    },
    entry: {
      state: deriveEntryState({ membershipState, inviteState }),
      activationState,
      canActivateLater: activationState === 'PENDING',
    },
  };
}
