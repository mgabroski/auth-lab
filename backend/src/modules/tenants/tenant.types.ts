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
 * Phase 9 (ADR 0003):
 * - setupCompletedAt: null = workspace has never been acknowledged by an admin
 *   visiting /admin/settings. The admin dashboard shows a setup banner.
 *   Once set (via POST /auth/workspace-setup-ack), the banner disappears for
 *   all admins in this workspace.
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

  /** Phase 9: null until any admin visits /admin/settings. */
  setupCompletedAt: Date | null;

  createdAt: Date;
  updatedAt: Date;
};
