/**
 * src/modules/auth/helpers/validate-invite-for-register.ts
 *
 * WHY:
 * - Invite validation is a distinct responsibility mixed inline in register().
 * - Extracting it makes the logic independently testable and clearly named.
 * - SSO invite-based registration (Brick 10) will reuse this.
 *
 * WHAT IT DOES:
 * - Hashes the raw invite token.
 * - Loads the invite for this tenant.
 * - Asserts status is ACCEPTED (not PENDING, EXPIRED, or CANCELLED).
 * - Asserts the invite email matches the registering email.
 *
 * RULES:
 * - Receives a trx-bound DbExecutor (caller owns the transaction).
 * - Throws AuthErrors — never returns a falsy value.
 * - email param must already be normalised (lowercase) by the caller.
 */

import type { DbExecutor } from '../../../shared/db/db';
import type { TokenHasher } from '../../../shared/security/token-hasher';
import type { Invite } from '../../invites/invite.types';
import { getInviteByTenantAndTokenHash } from '../../invites/invite.queries';
import { AuthErrors } from '../auth.errors';

export type ValidateInviteParams = {
  trx: DbExecutor;
  tokenHasher: TokenHasher;
  tenantId: string;
  inviteToken: string;
  /** Must be pre-normalised (lowercase). */
  email: string;
};

export async function validateInviteForRegister(params: ValidateInviteParams): Promise<Invite> {
  const { trx, tokenHasher, tenantId, inviteToken, email } = params;

  const tokenHash = tokenHasher.hash(inviteToken);
  const invite = await getInviteByTenantAndTokenHash(trx, { tenantId, tokenHash });

  if (!invite || invite.status !== 'ACCEPTED') {
    throw AuthErrors.inviteNotAccepted();
  }

  if (invite.email.toLowerCase() !== email) {
    throw AuthErrors.emailMismatch();
  }

  return invite;
}
