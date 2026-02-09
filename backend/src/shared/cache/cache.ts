/**
 * backend/src/shared/cache/cache.ts
 *
 * WHY:
 * - Rate limiting and other short-lived security state must be fast and externalized.
 * - We depend on an abstraction so tests can use an in-memory implementation.
 *
 * HOW TO USE:
 * - cache.get(key)
 * - cache.set(key, value, { ttlSeconds })
 * - cache.incr(key, { ttlSeconds }) -> counter with expiration
 */

export interface Cache {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, opts?: { ttlSeconds?: number }): Promise<void>;
  del(key: string): Promise<void>;

  /**
   * Atomically increment a counter and (optionally) ensure it expires.
   * Returns the new value.
   */
  incr(key: string, opts?: { ttlSeconds?: number }): Promise<number>;
}
