import { describe, it, expect } from 'vitest';
import { buildTestApp } from '../helpers/build-test-app';
import { UserRepo } from '../../src/modules/users/dal/user.repo';
import {
  selectUserByEmailSql,
  selectUserByIdSql,
} from '../../src/modules/users/dal/user.query-sql';
import { getUserByEmail } from '../../src/modules/users/queries/user.queries';

describe('users DAL', () => {
  it('insertUser creates a user and selectUserByEmail finds it', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const repo = new UserRepo(deps.db);
      const created = await repo.insertUser({ email: 'alice@example.com', name: 'Alice Smith' });

      expect(created.id).toBeDefined();
      expect(created.email).toBe('alice@example.com');

      const row = await selectUserByEmailSql(deps.db, 'alice@example.com');
      expect(row).toBeDefined();
      expect(row!.id).toBe(created.id);
      expect(row!.name).toBe('Alice Smith');

      await deps.db.deleteFrom('users').where('id', '=', created.id).execute();
    } finally {
      await close();
    }
  });

  it('normalizes email to lowercase', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const repo = new UserRepo(deps.db);
      const created = await repo.insertUser({ email: 'Bob@Example.COM', name: 'Bob' });

      expect(created.email).toBe('bob@example.com');

      const row = await selectUserByEmailSql(deps.db, 'BOB@EXAMPLE.COM');
      expect(row).toBeDefined();
      expect(row!.id).toBe(created.id);

      await deps.db.deleteFrom('users').where('id', '=', created.id).execute();
    } finally {
      await close();
    }
  });

  it('selectUserById returns correct user', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const repo = new UserRepo(deps.db);
      const created = await repo.insertUser({ email: 'charlie@example.com', name: null });

      const row = await selectUserByIdSql(deps.db, created.id);
      expect(row).toBeDefined();
      expect(row!.email).toBe('charlie@example.com');
      expect(row!.name).toBeNull();

      await deps.db.deleteFrom('users').where('id', '=', created.id).execute();
    } finally {
      await close();
    }
  });

  it('getUserByEmail returns shaped domain type', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const repo = new UserRepo(deps.db);
      const created = await repo.insertUser({ email: 'diana@example.com', name: 'Diana' });

      const user = await getUserByEmail(deps.db, 'diana@example.com');
      expect(user).toBeDefined();
      expect(user!.id).toBe(created.id);
      expect(user!.name).toBe('Diana');
      expect(user!.createdAt).toBeInstanceOf(Date);

      await deps.db.deleteFrom('users').where('id', '=', created.id).execute();
    } finally {
      await close();
    }
  });

  it('returns undefined for nonexistent user', async () => {
    const { deps, close } = await buildTestApp();
    try {
      const row = await selectUserByEmailSql(deps.db, 'nobody@nowhere.com');
      expect(row).toBeUndefined();
    } finally {
      await close();
    }
  });
});
