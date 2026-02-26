/**
 * backend/test/dal/auth-identities.spec.ts
 *
 * PR1 HARDENING ADDITIONS:
 * - insertSsoIdentity with ON CONFLICT DO NOTHING: sequential duplicate returns
 *   existing identity (no throw).
 * - insertSsoIdentity concurrent race: exactly one row, all requests succeed.
 */

import { describe, it, expect } from 'vitest';
import { buildTestApp } from '../helpers/build-test-app';
import { UserRepo } from '../../src/modules/users/dal/user.repo';
import { AuthRepo } from '../../src/modules/auth/dal/auth.repo';
import { selectAuthIdentityByUserAndProviderSql } from '../../src/modules/auth/dal/auth.query-sql';
import {
  getPasswordIdentityWithHash,
  hasAuthIdentity,
  findSsoIdentityByUserAndProvider,
} from '../../src/modules/auth/queries/auth.queries';

describe('auth identities DAL', () => {
  it('insertPasswordIdentity creates identity and select finds it', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const userRepo = new UserRepo(deps.db);
      const user = await userRepo.insertUser({ email: 'authtest@example.com', name: 'Auth' });

      const authRepo = new AuthRepo(deps.db);
      const identity = await authRepo.insertPasswordIdentity({
        userId: user.id,
        passwordHash: '$2b$12$fakehashfortest',
      });

      expect(identity.id).toBeDefined();

      const row = await selectAuthIdentityByUserAndProviderSql(deps.db, {
        userId: user.id,
        provider: 'password',
      });
      expect(row).toBeDefined();
      expect(row!.user_id).toBe(user.id);
      expect(row!.provider).toBe('password');
      expect(row!.password_hash).toBe('$2b$12$fakehashfortest');

      await deps.db.deleteFrom('auth_identities').where('user_id', '=', user.id).execute();
      await deps.db.deleteFrom('users').where('id', '=', user.id).execute();
    } finally {
      await close();
    }
  });

  it('getPasswordIdentityWithHash returns identity + hash', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const userRepo = new UserRepo(deps.db);
      const user = await userRepo.insertUser({ email: 'pwdquery@example.com', name: 'Pwd' });

      const authRepo = new AuthRepo(deps.db);
      await authRepo.insertPasswordIdentity({
        userId: user.id,
        passwordHash: '$2b$12$anotherhash',
      });

      const result = await getPasswordIdentityWithHash(deps.db, user.id);
      expect(result).toBeDefined();
      expect(result!.identity.userId).toBe(user.id);
      expect(result!.identity.provider).toBe('password');
      expect(result!.passwordHash).toBe('$2b$12$anotherhash');

      await deps.db.deleteFrom('auth_identities').where('user_id', '=', user.id).execute();
      await deps.db.deleteFrom('users').where('id', '=', user.id).execute();
    } finally {
      await close();
    }
  });

  it('hasAuthIdentity returns true/false correctly', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const userRepo = new UserRepo(deps.db);
      const user = await userRepo.insertUser({ email: 'hascheck@example.com', name: 'Has' });

      expect(await hasAuthIdentity(deps.db, { userId: user.id, provider: 'password' })).toBe(false);

      const authRepo = new AuthRepo(deps.db);
      await authRepo.insertPasswordIdentity({ userId: user.id, passwordHash: '$2b$12$hash' });

      expect(await hasAuthIdentity(deps.db, { userId: user.id, provider: 'password' })).toBe(true);
      expect(await hasAuthIdentity(deps.db, { userId: user.id, provider: 'google' })).toBe(false);

      await deps.db.deleteFrom('auth_identities').where('user_id', '=', user.id).execute();
      await deps.db.deleteFrom('users').where('id', '=', user.id).execute();
    } finally {
      await close();
    }
  });

  it('returns undefined for nonexistent user', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const result = await getPasswordIdentityWithHash(
        deps.db,
        '00000000-0000-0000-0000-000000000000',
      );
      expect(result).toBeUndefined();
    } finally {
      await close();
    }
  });

  // ───────────────────────────────────────────────────────────────────────────
  // SSO identity DAL
  // ───────────────────────────────────────────────────────────────────────────

  it('insertSsoIdentity creates row and findSsoIdentityByUserAndProvider retrieves it', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const userRepo = new UserRepo(deps.db);
      const user = await userRepo.insertUser({ email: 'sso-user@example.com', name: 'SSO' });

      const authRepo = new AuthRepo(deps.db);
      const inserted = await authRepo.insertSsoIdentity({
        userId: user.id,
        provider: 'google',
        providerSubject: 'sub-1',
      });

      expect(inserted.id).toBeDefined();

      const found = await findSsoIdentityByUserAndProvider(deps.db, {
        userId: user.id,
        provider: 'google',
      });

      expect(found).toBeDefined();
      expect(found!.userId).toBe(user.id);
      expect(found!.provider).toBe('google');
      expect(found!.providerSubject).toBe('sub-1');

      await deps.db.deleteFrom('auth_identities').where('user_id', '=', user.id).execute();
      await deps.db.deleteFrom('users').where('id', '=', user.id).execute();
    } finally {
      await close();
    }
  });

  it('findSsoIdentityByUserAndProvider returns undefined for nonexistent user/provider', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const result = await findSsoIdentityByUserAndProvider(deps.db, {
        userId: '00000000-0000-0000-0000-000000000000',
        provider: 'google',
      });
      expect(result).toBeUndefined();
    } finally {
      await close();
    }
  });

  it('findSsoIdentityByUserAndProvider is provider-scoped (google row not found for microsoft)', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const userRepo = new UserRepo(deps.db);
      const user = await userRepo.insertUser({ email: 'scope@example.com', name: 'Scope' });

      const authRepo = new AuthRepo(deps.db);
      await authRepo.insertSsoIdentity({
        userId: user.id,
        provider: 'google',
        providerSubject: 'sub-1',
      });

      const microsoft = await findSsoIdentityByUserAndProvider(deps.db, {
        userId: user.id,
        provider: 'microsoft',
      });
      expect(microsoft).toBeUndefined();

      await deps.db.deleteFrom('auth_identities').where('user_id', '=', user.id).execute();
      await deps.db.deleteFrom('users').where('id', '=', user.id).execute();
    } finally {
      await close();
    }
  });

  // ── PR1: Concurrency-safe SSO identity insert tests ───────────────────────

  it('sequential insertSsoIdentity for same user+provider returns existing identity without throwing', async () => {
    // Verifies ON CONFLICT DO NOTHING path on auth_identities(user_id, provider).
    // The second insert must return the first identity, not throw.
    const { deps, close } = await buildTestApp();
    try {
      const userRepo = new UserRepo(deps.db);
      const user = await userRepo.insertUser({
        email: 'sso-conflict-seq@example.com',
        name: 'SSO Sequential',
      });

      const authRepo = new AuthRepo(deps.db);

      const first = await authRepo.insertSsoIdentity({
        userId: user.id,
        provider: 'google',
        providerSubject: 'sub-original',
      });
      expect(first.id).toBeDefined();

      // Second insert same user+provider — must not throw, must return existing.
      const second = await authRepo.insertSsoIdentity({
        userId: user.id,
        provider: 'google',
        providerSubject: 'sub-duplicate', // different subject, same conflict key
      });

      // Same identity returned.
      expect(second.id).toBe(first.id);

      // Exactly one row in the DB for this user+provider.
      const rows = await deps.db
        .selectFrom('auth_identities')
        .selectAll()
        .where('user_id', '=', user.id)
        .where('provider', '=', 'google')
        .execute();

      expect(rows).toHaveLength(1);

      // Destructure the first element to avoid unnecessary type assertions.
      const [identity] = rows;

      // Original subject preserved — second insert was a no-op.
      expect(identity.provider_subject).toBe('sub-original');

      await deps.db.deleteFrom('auth_identities').where('user_id', '=', user.id).execute();
      await deps.db.deleteFrom('users').where('id', '=', user.id).execute();
    } finally {
      await close();
    }
  });

  it('concurrent insertSsoIdentity for same user+provider produces exactly one row and no errors', async () => {
    // Simulates concurrent OAuth callbacks racing for the same user+provider.
    // All must succeed (no 500), exactly one identity row must exist.
    const { deps, close } = await buildTestApp();
    try {
      const userRepo = new UserRepo(deps.db);
      const user = await userRepo.insertUser({
        email: 'sso-conflict-concurrent@example.com',
        name: 'SSO Concurrent',
      });

      const authRepo = new AuthRepo(deps.db);
      const concurrency = 5;

      const results = await Promise.all(
        Array.from({ length: concurrency }, (_, i) =>
          authRepo.insertSsoIdentity({
            userId: user.id,
            provider: 'google',
            providerSubject: `sub-racer-${i}`,
          }),
        ),
      );

      // All results must resolve (no rejections).
      expect(results).toHaveLength(concurrency);
      for (const result of results) {
        expect(result.id).toBeDefined();
      }

      // All returned ids must be the same identity.
      const uniqueIds = new Set(results.map((r) => r.id));
      expect(uniqueIds.size).toBe(1);

      // Exactly one row in the DB.
      const rows = await deps.db
        .selectFrom('auth_identities')
        .selectAll()
        .where('user_id', '=', user.id)
        .where('provider', '=', 'google')
        .execute();
      expect(rows).toHaveLength(1);

      await deps.db.deleteFrom('auth_identities').where('user_id', '=', user.id).execute();
      await deps.db.deleteFrom('users').where('id', '=', user.id).execute();
    } finally {
      await close();
    }
  });

  it('insertSsoIdentity is provider-scoped — same user can have google AND microsoft identities', async () => {
    // Verifies the UNIQUE(user_id, provider) constraint doesn't block
    // legitimate multi-provider scenarios.
    const { deps, close } = await buildTestApp();
    try {
      const userRepo = new UserRepo(deps.db);
      const user = await userRepo.insertUser({
        email: 'multi-provider@example.com',
        name: 'Multi',
      });

      const authRepo = new AuthRepo(deps.db);

      const google = await authRepo.insertSsoIdentity({
        userId: user.id,
        provider: 'google',
        providerSubject: 'google-sub',
      });

      const microsoft = await authRepo.insertSsoIdentity({
        userId: user.id,
        provider: 'microsoft',
        providerSubject: 'ms-sub',
      });

      // Different ids — these are distinct identities.
      expect(google.id).not.toBe(microsoft.id);

      const rows = await deps.db
        .selectFrom('auth_identities')
        .selectAll()
        .where('user_id', '=', user.id)
        .execute();
      expect(rows).toHaveLength(2);

      await deps.db.deleteFrom('auth_identities').where('user_id', '=', user.id).execute();
      await deps.db.deleteFrom('users').where('id', '=', user.id).execute();
    } finally {
      await close();
    }
  });
});
