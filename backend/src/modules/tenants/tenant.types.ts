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

  createdAt: Date;
  updatedAt: Date;
};
