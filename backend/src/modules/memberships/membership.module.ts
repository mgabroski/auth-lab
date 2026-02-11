/**
 * backend/src/modules/memberships/membership.module.ts
 *
 * WHY:
 * - Encapsulates Memberships module wiring.
 * - Support module (no routes of its own).
 *   Other modules (auth, admin) consume its repo/queries/policies.
 *
 * RULES:
 * - No infra creation here (DI passes deps in).
 * - No globals/singletons here.
 */

import type { DbExecutor } from '../../shared/db/db';
import { MembershipRepo } from './dal/membership.repo';

export type MembershipModule = ReturnType<typeof createMembershipModule>;

export function createMembershipModule(deps: { db: DbExecutor }) {
  const membershipRepo = new MembershipRepo(deps.db);

  return {
    membershipRepo,
  };
}
