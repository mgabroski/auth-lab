/**
 * backend/src/modules/tenants/policies/tenant-access.policy.ts
 *
 * WHY:
 * - Email domain allow-listing is a tenant-level access rule, not an
 *   orchestration detail. Policy functions belong in policies/, not in flow files.
 * - The same rule is needed by SSO (Brick 10) and public signup (Brick 11).
 *   A single definition here prevents drift and ensures both flows behave
 *   identically without duplicating the logic.
 *
 * RULES:
 * - Pure functions: no DB access, no I/O, no side effects.
 * - Throws AppError (TenantErrors) for policy violations.
 * - Does NOT import from auth, users, or memberships modules.
 *
 * CONSUMERS:
 * - SSO flow (Brick 10): calls isEmailDomainAllowed() — needs the boolean
 *   to wrap the failure in SsoDeniedError for audit context.
 * - Public signup (Brick 11): calls assertEmailDomainAllowed() — can throw
 *   directly since it does not use the SsoDeniedError carrier pattern.
 */

import { emailDomain } from '../../../shared/utils/email-domain';
import { TenantErrors } from '../tenant.errors';
import type { Tenant } from '../tenant.types';

/**
 * Pure predicate: returns true if the email's domain is permitted by the tenant,
 * or if the tenant has no domain restriction configured (empty allowedEmailDomains).
 *
 * Use this when the caller needs to control what error is thrown
 * (e.g. SSO flow wraps into SsoDeniedError for audit context).
 */
export function isEmailDomainAllowed(tenant: Tenant, email: string): boolean {
  if (!tenant.allowedEmailDomains.length) return true;
  const domain = emailDomain(email);
  if (!domain) return false;
  return tenant.allowedEmailDomains.includes(domain);
}

/**
 * Assert variant: throws TenantErrors.emailDomainNotAllowed() when the
 * email domain is not permitted.
 *
 * Use this when the caller can throw directly without wrapping
 * (e.g. public signup flow in Brick 11).
 */
export function assertEmailDomainAllowed(tenant: Tenant, email: string): void {
  if (!isEmailDomainAllowed(tenant, email)) {
    throw TenantErrors.emailDomainNotAllowed();
  }
}
