/**
 * backend/src/shared/security/password-hasher.ts
 *
 * WHY:
 * - Password hashing must be consistent, safe, and easy to swap.
 * - Services should depend on an interface (DIP), not bcrypt directly.
 *
 * HOW TO USE:
 * - const hash = await hasher.hash(password)
 * - const ok = await hasher.verify(password, hash)
 */

export interface PasswordHasher {
  hash(plain: string): Promise<string>;
  verify(plain: string, hash: string): Promise<boolean>;
}
