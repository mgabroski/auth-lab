/**
 * src/shared/security/keyed-hasher.ts
 *
 * WHY:
 * - Recovery codes are shorter than invite/reset tokens (16 chars vs 32 bytes),
 *   which makes them more vulnerable to offline dictionary attacks if their
 *   hashes are leaked from the DB.
 * - HMAC-SHA256(code, MFA_HMAC_KEY) adds a server-side pepper: an attacker who
 *   obtains the mfa_recovery_codes table still cannot crack the codes without
 *   also possessing MFA_HMAC_KEY from the environment.
 * - Lookup on consumption is identical: hash the submitted code with the same
 *   key, query for the matching row.
 *
 * WHY NOT SHA-256 (like invite/reset tokens)?
 * - Invite tokens: 32 random bytes base64url = 256 bits entropy.
 *   Offline dictionary attacks are computationally infeasible even with plain SHA-256.
 * - Recovery codes: 16 alphanumeric chars ≈ 82 bits entropy.
 *   Lower entropy makes keyed hashing a meaningful security improvement.
 *
 * KEY:
 * - MFA_HMAC_KEY from environment (min 32 chars, validated at startup).
 * - Generate with: openssl rand -base64 32
 *
 * RULES:
 * - Deterministic: same (input, key) → same output (required for DB lookup).
 * - No DB access. No business logic.
 */

import { createHmac } from 'node:crypto';

export interface KeyedHasher {
  hash(value: string): string;
}

export class HmacSha256KeyedHasher implements KeyedHasher {
  private readonly key: string;

  constructor(key: string) {
    if (key.length < 32) {
      throw new Error(
        `HmacSha256KeyedHasher: key must be at least 32 characters. Got ${key.length}.`,
      );
    }
    this.key = key;
  }

  /**
   * Returns HMAC-SHA256(value, key) as a lowercase hex string.
   * Deterministic — same value + key always produces the same hash.
   */
  hash(value: string): string {
    return createHmac('sha256', this.key).update(value).digest('hex');
  }
}
