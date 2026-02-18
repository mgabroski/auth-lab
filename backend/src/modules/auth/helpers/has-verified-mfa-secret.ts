/**
 * backend/src/modules/auth/helpers/has-verified-mfa-secret.ts
 *
 * WHY:
 * - Deep module: answer a single question used by flows/policies:
 *   "Does this user have a verified MFA secret configured?"
 * - Hides query shape and reduces duplication across flows.
 *
 * RULES:
 * - No HTTP.
 * - No DB writes.
 * - Thin wrapper over auth query.
 */

import type { DbExecutor } from '../../../shared/db/db';
import { getMfaSecretForUser } from '../queries/mfa.queries';

export async function hasVerifiedMfaSecret(db: DbExecutor, userId: string): Promise<boolean> {
  const row = await getMfaSecretForUser(db, userId);
  return Boolean(row?.isVerified);
}
