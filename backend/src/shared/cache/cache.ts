/**
 * src/shared/cache/cache.ts
 *
 * WHY:
 * - Rate limiting and other short-lived security state must be fast and externalized.
 * - We depend on an abstraction so tests can use an in-memory implementation.
 *
 * HOW TO USE:
 * - cache.get(key)
 * - cache.set(key, value, { ttlSeconds })
 * - cache.set(key, value, { keepTtl: true })  // do NOT refresh TTL
 * - cache.incr(key, { ttlSeconds }) -> counter with expiration
 * - cache.sadd / smembers / srem -> Redis SET semantics for user-session index
 */

export interface CacheSetOptions {
  ttlSeconds?: number;

  /**
   * Keep existing TTL when overwriting a key.
   *
   * Used by Brick 9 MFA flows: update the session payload (mfaVerified) WITHOUT
   * extending session lifetime.
   *
   * Redis supports this via SET ... KEEPTTL.
   * InMemCache preserves the existing expiry timestamp.
   */
  keepTtl?: boolean;
}

export interface Cache {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, opts?: CacheSetOptions): Promise<void>;
  del(key: string): Promise<void>;

  /**
   * Atomically increment a counter and (optionally) ensure it expires.
   * Returns the new value.
   */
  incr(key: string, opts?: { ttlSeconds?: number }): Promise<number>;

  /**
   * Add a member to a set. Idempotent — adding an existing member is a no-op.
   * Optionally refresh the TTL on the set key.
   */
  sadd(key: string, member: string, opts?: { ttlSeconds?: number }): Promise<void>;

  /**
   * Return all members of a set, or an empty array if the key does not exist.
   */
  smembers(key: string): Promise<string[]>;

  /**
   * Remove a member from a set. No-op if the member is not present.
   */
  srem(key: string, member: string): Promise<void>;
}
