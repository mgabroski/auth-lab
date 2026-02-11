import { describe, it, expect } from 'vitest';
import { buildTestApp } from '../helpers/build-test-app';
import { UserRepo } from '../../src/modules/users/dal/user.repo';
import { AuthRepo } from '../../src/modules/auth/dal/auth.repo';
import { selectAuthIdentityByUserAndProviderSql } from '../../src/modules/auth/dal/auth.query-sql';
import { getPasswordIdentityWithHash, hasAuthIdentity } from '../../src/modules/auth/auth.queries';

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
});
