/**
 * src/shared/cache/redis-cache.ts
 */

import { createClient } from 'redis';
import type { Cache, CacheSetOptions } from './cache';
import { logger } from '../logger/logger';

type RedisClient = ReturnType<typeof createClient>;

export class RedisCache implements Cache {
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
    // NOTE:
    // - If ttlSeconds is provided: set with EX.
    // - If keepTtl is true: set with KEEPTTL (does not change existing TTL).
    // - If neither provided: plain set.
    //
    // If both are provided, ttlSeconds wins (explicit TTL is intentional).
    if (opts?.ttlSeconds !== undefined) {
      await this.client.set(key, value, { EX: opts.ttlSeconds });
      return;
    }

    if (opts?.keepTtl) {
      // Redis >= 6 supports KEEPTTL.
      await this.client.set(key, value, { KEEPTTL: true });
      return;
    }

    await this.client.set(key, value);
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async incr(key: string, opts?: { ttlSeconds?: number }): Promise<number> {
    const value = await this.client.incr(key);

    if (opts?.ttlSeconds) {
      const ttl = await this.client.ttl(key);
      if (ttl < 0) {
        await this.client.expire(key, opts.ttlSeconds);
      }
    }

    return value;
  }

  async sadd(key: string, member: string, opts?: { ttlSeconds?: number }): Promise<void> {
    await this.client.sAdd(key, member);

    if (opts?.ttlSeconds) {
      await this.client.expire(key, opts.ttlSeconds);
    }
  }

  async smembers(key: string): Promise<string[]> {
    return this.client.sMembers(key);
  }

  async srem(key: string, member: string): Promise<void> {
    await this.client.sRem(key, member);
  }
}
