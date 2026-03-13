/**
 * backend/src/modules/auth/helpers/resolve-tenant-entry-auth-decision.ts
 *
 * WHY:
 * - Phase 1B runtime flows need one shared way to turn (tenant + email) into the
 *   normalized Phase 1A policy input and Phase 1A.5 decision.
 * - This keeps signup and SSO callback aligned to the same tenant-entry truth
 *   instead of each flow re-deriving invite/membership state independently.
 *
 * RULES:
 * - Read-side only: no mutations, no HTTP concerns, no audits.
 * - Uses module public surfaces (users / memberships / invites / policies).
 * - Returns both the loaded entities and the computed decision so callers can
 *   enforce runtime behavior without duplicating query work.
 */

import type { DbExecutor } from '../../../shared/db/db';
import { buildTenantEntryPolicyInput } from '../../_shared/policies/tenant-entry-policy-input';
import {
  decideTenantEntryAuthPolicy,
  type AuthEntryPolicyDecision,
} from '../../_shared/policies/tenant-entry-auth-policy';
import { getMembershipByTenantAndUser } from '../../memberships';
import type { Membership } from '../../memberships/membership.types';
import type { Tenant } from '../../tenants';
import { getUserByEmail } from '../../users';
import type { User } from '../../users/user.types';
import { getLatestInviteByTenantAndEmail } from '../../invites';
import type { Invite } from '../../invites';

export type ResolvedTenantEntryAuthDecision = {
  tenant: Tenant;
  user: User | undefined;
  membership: Membership | undefined;
  invite: Invite | undefined;
  input: ReturnType<typeof buildTenantEntryPolicyInput>;
  decision: AuthEntryPolicyDecision;
};

export async function resolveTenantEntryAuthDecision(params: {
  db: DbExecutor;
  tenant: Tenant;
  email: string;
  now?: Date;
}): Promise<ResolvedTenantEntryAuthDecision> {
  const now = params.now ?? new Date();

  const user = await getUserByEmail(params.db, params.email);
  const membership = user
    ? await getMembershipByTenantAndUser(params.db, {
        tenantId: params.tenant.id,
        userId: user.id,
      })
    : undefined;

  const invite = await getLatestInviteByTenantAndEmail(params.db, {
    tenantId: params.tenant.id,
    email: params.email,
  });

  const input = buildTenantEntryPolicyInput({
    tenant: params.tenant,
    membership,
    invite,
    now,
  });

  const decision = decideTenantEntryAuthPolicy(input);

  return {
    tenant: params.tenant,
    user,
    membership,
    invite,
    input,
    decision,
  };
}
