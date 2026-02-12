/**
 * backend/src/shared/cache/redis-cache.ts
 *
 * WHY:
 * - Redis implementation of Cache used for rate limiting, tokens, small ephemeral state.
 *
 * IMPORTANT:
 * - In monorepos, importing RedisClientType can cause type conflicts if multiple copies of
 *   @redis/client exist. We avoid that by deriving the client type from createClient().
 *
 * LOGGING:
 * - Redis connection errors fire outside any request context (they are client-level events,
 *   not request-level). We use the global logger directly — withRequestContext() is not
 *   applicable here. This is the same approach used by logger.ts for app-level concerns.
 */

import { createClient } from 'redis';
import type { Cache } from './cache';
import { logger } from '../logger/logger';

type RedisClient = ReturnType<typeof createClient>;

export class RedisCache implements Cache {
  private constructor(private readonly client: RedisClient) {}

  static async connect(redisUrl: string): Promise<RedisCache> {
    const client = createClient({ url: redisUrl });

    client.on('error', (err: Error) => {
      // Connection-level error: no request context available.
      // Structured JSON log routes through the same transport as all other logs.
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
