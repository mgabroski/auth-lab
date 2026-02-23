export type TenantKey = string;

export type TenantAllowedEmailDomains = string[];

export type TenantAllowedSso = string[];

/**
 * Tenant = Workspace (UI term)
 * Resolved ONLY by URL/subdomain (tenantKey).
 */
export type Tenant = {
  id: string;
  key: TenantKey;
  name: string;

  isActive: boolean;

  publicSignupEnabled: boolean;
  memberMfaRequired: boolean;

  allowedEmailDomains: TenantAllowedEmailDomains;
  allowedSso: TenantAllowedSso;

  createdAt: Date;
  updatedAt: Date;
};
