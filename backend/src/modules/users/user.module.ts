/**
 * backend/src/modules/users/user.module.ts
 *
 * WHY:
 * - Encapsulates Users module wiring.
 * - Users module is a support module (no routes of its own).
 *   Other modules (auth, admin) consume its repo/queries.
 *
 * RULES:
 * - No infra creation here (DI passes deps in).
 * - No globals/singletons here.
 */

import type { DbExecutor } from '../../shared/db/db';
import { UserRepo } from './dal/user.repo';

export type UserModule = ReturnType<typeof createUserModule>;

export function createUserModule(deps: { db: DbExecutor }) {
  const userRepo = new UserRepo(deps.db);

  return {
    userRepo,
  };
}
