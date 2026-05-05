export type TenantKey = string;

export type TenantAllowedEmailDomains = string[];

export type TenantAllowedSso = string[];

/**
 * Tenant = Workspace (UI term)
 * Resolved ONLY by URL/subdomain (tenantKey).
 *
 * Phase 1A note:
 * - adminInviteRequired is explicit policy input from the provisioning spec.
 * - It exists separately from publicSignupEnabled because later phases need to
 *   distinguish "signup available" from "invite required" without inferring one
 *   rule from the other.
 *
 * Legacy scaffold note:
 * - setupCompletedAt stores the retired auth-phase acknowledgement timestamp.
 * - The current admin pages do not read this timestamp for live Settings
 *   progress. It remains only for auth/config compatibility and conservative
 *   migration/backfill handling.
 */
export type Tenant = {
  id: string;
  key: TenantKey;
  name: string;

  isActive: boolean;

  publicSignupEnabled: boolean;
  adminInviteRequired: boolean;
  memberMfaRequired: boolean;

  allowedEmailDomains: TenantAllowedEmailDomains;
  allowedSso: TenantAllowedSso;

  /** Retired auth-phase acknowledgement timestamp retained for compatibility. */
  setupCompletedAt: Date | null;

  createdAt: Date;
  updatedAt: Date;
};
