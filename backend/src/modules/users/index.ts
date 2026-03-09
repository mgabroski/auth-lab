/**
 * backend/src/modules/users/index.ts
 *
 * WHY:
 * - Define the public surface of the users module.
 * - Prevent cross-module coupling via deep imports into /queries or /dal.
 *
 * RULES:
 * - Only export stable contracts needed by other modules.
 * - Keep exports minimal; add more only when explicitly required.
 *
 * EXPORTS:
 * - Read-only queries: getUserByEmail, getUserById
 * - Shared use case:   findOrCreateUser  (registration, SSO, public signup)
 * - Domain type:       User
 */

export { getUserByEmail, getUserById } from './queries/user.queries';
export { findOrCreateUser } from './use-cases/find-or-create-user';
export type { FindOrCreateUserResult } from './use-cases/find-or-create-user';
export type { User } from './user.types';

export type { UserRepo } from './dal/user.repo';
