/**
 * src/modules/auth/helpers/ensure-password-identity.ts
 *
 * WHY:
 * - Password identity creation has its own guard (reject if already exists),
 *   hash step, and insert — a distinct responsibility from user provisioning.
 * - Extracting it makes the replay-guard logic independently testable.
 *
 * WHAT IT DOES:
 * - Checks if a password identity already exists for this user.
 * - Throws AuthErrors.alreadyRegistered if it does (replay guard).
 * - Hashes the raw password.
 * - Inserts the new password identity.
 *
 * RULES:
 * - Receives a trx-bound authRepo (caller owns the transaction).
 * - Never logs or returns the raw password or hash.
 * - Throws AuthErrors — never returns a falsy value.
 */

import type { PasswordHasher } from '../../../shared/security/password-hasher';
import type { AuthRepo } from '../dal/auth.repo';
import { getPasswordIdentityWithHash } from '../queries/auth.queries';
import { AuthErrors } from '../auth.errors';
import type { DbExecutor } from '../../../shared/db/db';

export type EnsurePasswordIdentityParams = {
  trx: DbExecutor;
  authRepo: AuthRepo;
  passwordHasher: PasswordHasher;
  userId: string;
  rawPassword: string;
};

export async function ensurePasswordIdentity(params: EnsurePasswordIdentityParams): Promise<void> {
  const { trx, authRepo, passwordHasher, userId, rawPassword } = params;

  const existing = await getPasswordIdentityWithHash(trx, userId);
  if (existing) {
    throw AuthErrors.alreadyRegistered();
  }

  const passwordHash = await passwordHasher.hash(rawPassword);
  await authRepo.insertPasswordIdentity({ userId, passwordHash });
}
