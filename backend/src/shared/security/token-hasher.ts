/**
 * backend/src/shared/security/token-hasher.ts
 *
 * WHY:
 * - We never store raw security tokens in the database (invite/reset tokens).
 * - We store only a hash (SHA-256) so a DB leak doesn't expose usable tokens.
 *
 * HOW TO USE:
 * - Generate raw token -> hash it -> store hash in DB
 * - When user presents token -> hash -> compare with stored hash
 *
 * NOTE:
 * - This is intentionally an interface: callers depend on an abstraction (DIP).
 * - Today we implement SHA-256. Tomorrow we can switch without touching services.
 */

export interface TokenHasher {
  hash(rawToken: string): string;
}
