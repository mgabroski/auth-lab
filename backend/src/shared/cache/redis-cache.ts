/**
 * backend/src/shared/cache/redis-cache.ts
 *
 * WHY:
 * - Redis implementation of Cache used for rate limiting, tokens, small ephemeral state.
 *
 * IMPORTANT:
 * - In monorepos, importing RedisClientType can cause type conflicts if multiple copies of
 *   @redis/client exist. We avoid that by deriving the client type from createClient().
 */

import { createClient } from 'redis';
import type { Cache } from './cache';

type RedisClient = ReturnType<typeof createClient>;

export class RedisCache implements Cache {
  private constructor(private readonly client: RedisClient) {}

  static async connect(redisUrl: string): Promise<RedisCache> {
    const client = createClient({ url: redisUrl });

    client.on('error', (err) => {
      console.error('Redis client error', err);
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

  async set(key: string, value: string, opts?: { ttlSeconds?: number }): Promise<void> {
    if (opts?.ttlSeconds) {
      await this.client.set(key, value, { EX: opts.ttlSeconds });
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
}
