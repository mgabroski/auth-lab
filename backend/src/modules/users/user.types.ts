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
 *
 * - Added emailVerified: boolean (mirrors users.email_verified).
 * - DEFAULT true in DB means all existing users (invite, admin, SSO) are
 *   already verified. Only public signup creates users with emailVerified = false.
 */

export type UserId = string;

export type User = {
  id: UserId;
  email: string;
  name: string | null;

  /**
   * Whether the user has verified their email address.
   *
   * true  — all users created via invite, admin, or SSO (identity already proven).
   * false — new users created via public password signup until they click the
   *         verification link.
   *
   * DEFAULT true in DB.
   */
  emailVerified: boolean;

  createdAt: Date;
  updatedAt: Date;
};
