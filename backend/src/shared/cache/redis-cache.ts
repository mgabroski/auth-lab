/**
 * src/shared/cache/redis-cache.ts
 *
 * X4 — Atomic INCR+EXPIRE via Lua script:
 * - Previously: incr() ran INCR → TTL read → conditional EXPIRE as three
 *   separate commands. A process crash between INCR and EXPIRE produced a key
 *   with no TTL. That key accumulated forever, permanently rate-locking users.
 * - Fix: when ttlSeconds is provided, a single Lua script executes INCR and
 *   EXPIRE atomically in one Redis round-trip.
 * - EXPIRE is only set when the counter reaches 1 (first increment in the
 *   window). Subsequent increments do NOT reset the TTL — this is correct
 *   sliding-window semantics. Resetting TTL on every increment would allow an
 *   attacker to keep a window alive indefinitely with steady requests.
 * - When ttlSeconds is NOT provided, plain this.client.incr() is used — no
 *   Lua overhead, no behavior change for callers that don't need expiry.
 *
 * 9/10 HARDENING — X11: Atomic SADD+EXPIRE via Lua script:
 * - Previously: sadd() ran sAdd then conditionally called expire() as two
 *   separate commands. This is the same class of bug X4 fixed for incr().
 *   A process crash between SADD and EXPIRE left the user-session index key
 *   (session:user:{hashedUserId}) with no TTL. That key persisted indefinitely,
 *   accumulating stale session IDs.
 * - Fix: SADD_EXPIRE_SCRIPT atomically executes SADD and EXPIRE in one
 *   round-trip. EXPIRE is only set when the key did not previously exist
 *   (i.e., when SADD created the key), preserving correct TTL semantics.
 *   Subsequent adds to an existing set do NOT reset the TTL.
 * - When ttlSeconds is NOT provided, plain this.client.sAdd() is used.
 */

import { createClient } from 'redis';
import type { Cache, CacheSetOptions } from './cache';
import { logger } from '../logger/logger';

type RedisClient = ReturnType<typeof createClient>;

export class RedisCache implements Cache {
  private static readonly INCR_EXPIRE_SCRIPT = `
    local v = redis.call("INCR", KEYS[1])
    if v == 1 then
      redis.call("EXPIRE", KEYS[1], ARGV[1])
    end
    return v
  `;

  /**
   * SADD + conditional EXPIRE in one atomic Lua round-trip.
   *
   * Logic:
   * 1. SADD the member to the set.
   * 2. If the set did not exist before this call (EXISTS returns 0 after SADD
   *    would mean the key is new), set EXPIRE.
   *
   * We detect "key is new" by checking SCARD before and after is expensive.
   * Instead we use EXISTS before SADD: if the key did not exist, this is the
   * first add and we should set the TTL.
   *
   * This preserves correct TTL semantics: subsequent adds within the same
   * session lifetime window do not reset the expiry.
   */
  private static readonly SADD_EXPIRE_SCRIPT = `
    local existed = redis.call("EXISTS", KEYS[1])
    redis.call("SADD", KEYS[1], ARGV[1])
    if existed == 0 then
      redis.call("EXPIRE", KEYS[1], ARGV[2])
    end
    return 1
  `;

  private constructor(private readonly client: RedisClient) {}

  static async connect(redisUrl: string): Promise<RedisCache> {
    const client = createClient({ url: redisUrl });

    client.on('error', (err: Error) => {
      logger.error('redis.client_error', {
        flow: 'redis',
        message: err.message,
        stack: err.stack,
      });
    });

    await client.connect();
    return new RedisCache(client);
  }

  async close(): Promise<void> {
    await this.client.quit();
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async set(key: string, value: string, opts?: CacheSetOptions): Promise<void> {
    if (opts?.ttlSeconds !== undefined) {
      await this.client.set(key, value, { EX: opts.ttlSeconds });
      return;
    }

    if (opts?.keepTtl) {
      await this.client.set(key, value, { KEEPTTL: true });
      return;
    }

    await this.client.set(key, value);
  }

  async setIfAbsent(key: string, value: string, opts?: { ttlSeconds?: number }): Promise<boolean> {
    const res = await this.client.set(key, value, {
      NX: true,
      ...(opts?.ttlSeconds !== undefined ? { EX: opts.ttlSeconds } : {}),
    });

    return res === 'OK';
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async delMany(keys: string[]): Promise<void> {
    if (keys.length === 0) return;
    await this.client.del(keys);
  }

  async incr(key: string, opts?: { ttlSeconds?: number }): Promise<number> {
    if (!opts?.ttlSeconds) {
      return this.client.incr(key);
    }

    const result = await this.client.eval(RedisCache.INCR_EXPIRE_SCRIPT, {
      keys: [key],
      arguments: [String(opts.ttlSeconds)],
    });

    return result as number;
  }

  /**
   * X11: Atomic SADD + EXPIRE via Lua script.
   *
   * When ttlSeconds is provided, the operation is atomic: SADD and EXPIRE
   * happen in a single Redis round-trip with no window for a crash between them.
   *
   * EXPIRE is only set when the key did not already exist — subsequent adds
   * within the same window do not reset the expiry, which is correct behavior
   * for the user-session index (session:user:{hashedUserId}).
   */
  async sadd(key: string, member: string, opts?: { ttlSeconds?: number }): Promise<void> {
    if (!opts?.ttlSeconds) {
      await this.client.sAdd(key, member);
      return;
    }

    await this.client.eval(RedisCache.SADD_EXPIRE_SCRIPT, {
      keys: [key],
      arguments: [member, String(opts.ttlSeconds)],
    });
  }

  async smembers(key: string): Promise<string[]> {
    return this.client.sMembers(key);
  }

  async srem(key: string, member: string): Promise<void> {
    await this.client.sRem(key, member);
  }
}
