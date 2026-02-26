/**
 * backend/test/dal/users.spec.ts
 *
 * - Sequential insert same email → existing user returned, no error thrown.
 * - Concurrent insert same email → exactly one row, all requests succeed.
 */

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

  // ── PR1: Concurrency-safe insert tests ────────────────────────────────────

  it('sequential insert with same email returns the existing user without throwing', async () => {
    // Verifies ON CONFLICT DO NOTHING path: second insert returns first user.
    const { deps, close } = await buildTestApp();
    try {
      const repo = new UserRepo(deps.db);
      const email = 'conflict-sequential@example.com';

      const first = await repo.insertUser({ email, name: 'First' });
      expect(first.id).toBeDefined();

      // Second insert for the same email — must not throw, must return first user.
      const second = await repo.insertUser({ email, name: 'Second' });

      // Same user returned — id matches, no duplicate row created.
      expect(second.id).toBe(first.id);
      expect(second.email).toBe(first.email);

      // DB has exactly one row for this email.
      const rows = await deps.db
        .selectFrom('users')
        .selectAll()
        .where('email', '=', email)
        .execute();
      expect(rows).toHaveLength(1);

      await deps.db.deleteFrom('users').where('id', '=', first.id).execute();
    } finally {
      await close();
    }
  });

  it('concurrent inserts with same email produce exactly one row and no errors', async () => {
    // Simulates N simultaneous requests racing on the same email.
    // All must succeed (no 500), exactly one DB row must exist.
    const { deps, close } = await buildTestApp();
    try {
      const repo = new UserRepo(deps.db);
      const email = 'conflict-concurrent@example.com';
      const concurrency = 5;

      const results = await Promise.all(
        Array.from({ length: concurrency }, (_, i) =>
          repo.insertUser({ email, name: `Racer ${i}` }),
        ),
      );

      // All results must resolve (no rejections).
      expect(results).toHaveLength(concurrency);
      for (const result of results) {
        expect(result.id).toBeDefined();
        expect(result.email).toBe(email);
      }

      // All returned ids must be the same user.
      const uniqueIds = new Set(results.map((r) => r.id));
      expect(uniqueIds.size).toBe(1);

      // Exactly one row in the DB.
      const rows = await deps.db
        .selectFrom('users')
        .selectAll()
        .where('email', '=', email)
        .execute();
      expect(rows).toHaveLength(1);

      await deps.db.deleteFrom('users').where('email', '=', email).execute();
    } finally {
      await close();
    }
  });
});
