/**
 * backend/src/modules/users/index.ts
 *
 * WHY:
 * - Define the public surface of the users module.
 * - Prevent cross-module coupling via deep imports into /queries or /dal.
 *
 * RULES:
 * - Only export stable, read-only contracts needed by other modules.
 * - Keep exports minimal; add more only when explicitly required.
 */

export { getUserByEmail, getUserById } from './queries/user.queries';
export type { User } from './user.types';
