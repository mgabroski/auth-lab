/**
 * src/modules/auth/mfa.queries.ts
 *
 * WHY:
 * - Read-only query facades that shape raw DB rows into domain types.
 * - Service-layer entry point for MFA reads.
 *
 * RULES:
 * - No mutations.
 * - No AppError (caller handles null).
 * - Side-effect free.
 */

import type { DbExecutor } from '../../../shared/db/db';
import { selectMfaSecretByUser } from '../dal/mfa.query-sql';

export type MfaSecret = {
  id: string;
  userId: string;
  secretEncrypted: string;
  isVerified: boolean;
  createdAt: Date;
  verifiedAt: Date | null;
};

export async function getMfaSecretForUser(
  db: DbExecutor,
  userId: string,
): Promise<MfaSecret | null> {
  return selectMfaSecretByUser(db, userId);
}
