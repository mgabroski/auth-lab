/**
 * backend/src/modules/users/user.types.ts
 *
 * WHY:
 * - Domain types for the Users module.
 * - Users are global identities (not tenant-scoped).
 * - One email = one user across all tenants.
 *
 * RULES:
 * - Keep aligned with DB schema.
 * - Avoid leaking DB naming (snake_case) outside DAL/queries.
 */

export type UserId = string;

export type User = {
  id: UserId;
  email: string;
  name: string | null;

  createdAt: Date;
  updatedAt: Date;
};
