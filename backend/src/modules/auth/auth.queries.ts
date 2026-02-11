/**
 * backend/src/modules/auth/auth.queries.ts
 *
 * WHY:
 * - Queries are read-only and side-effect free.
 * - Shape auth_identity rows into domain types.
 * - Exposes password hash separately for verification (never in domain type).
 *
 * RULES:
 * - Read-only.
 * - No AppError.
 */

import type { DbExecutor } from '../../shared/db/db';
import { selectAuthIdentityByUserAndProviderSql } from './dal/auth.query-sql';
import type { AuthIdentity, AuthProvider } from './auth.types';

function parseProvider(value: string): AuthProvider {
  if (value === 'password' || value === 'google' || value === 'microsoft') return value;
  return 'password';
}

/**
 * Returns the password auth identity including the hash (for verification).
 * The hash is returned separately — it is NOT part of the AuthIdentity domain type.
 */
export async function getPasswordIdentityWithHash(
  db: DbExecutor,
  userId: string,
): Promise<{ identity: AuthIdentity; passwordHash: string } | undefined> {
  const row = await selectAuthIdentityByUserAndProviderSql(db, {
    userId,
    provider: 'password',
  });

  if (!row) return undefined;
  if (!row.password_hash) return undefined; // safety: DB constraint should prevent this

  return {
    identity: {
      id: row.id,
      userId: row.user_id,
      provider: parseProvider(row.provider),
      providerSubject: row.provider_subject ?? null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    },
    passwordHash: row.password_hash,
  };
}

/**
 * Checks if a user has any auth identity for a given provider.
 */
export async function hasAuthIdentity(
  db: DbExecutor,
  params: { userId: string; provider: string },
): Promise<boolean> {
  const row = await selectAuthIdentityByUserAndProviderSql(db, params);
  return !!row;
}
