/**
 * backend/src/app/di.ts
 *
 * WHY:
 * - Single dependency graph for the whole app.
 * - Creates infra clients ONCE (db, redis) and shares them safely.
 * - Keeps modules testable (later we can inject fakes).
 *
 * HOW TO USE:
 * - Called from build-app.ts (later) or index.ts for now.
 * - Returns a `deps` object passed into server/module builders.
 *
 * RULES:
 * - No business logic here.
 * - No HTTP logic here.
 */

import type { AppConfig } from './config';
import { createDb } from '../shared/db/db';

import { RedisCache } from '../shared/cache/redis-cache';
import type { Cache } from '../shared/cache/cache';

import { RateLimiter } from '../shared/security/rate-limit';
import type { TokenHasher } from '../shared/security/token-hasher';
import { Sha256TokenHasher } from '../shared/security/sha256-token-hasher';

import type { PasswordHasher } from '../shared/security/password-hasher';
import { BcryptPasswordHasher } from '../shared/security/bcrypt-password-hasher';

export type AppDeps = {
  db: ReturnType<typeof createDb>;
  cache: Cache;

  rateLimiter: RateLimiter;
  tokenHasher: TokenHasher;
  passwordHasher: PasswordHasher;

  // lifecycle
  close: () => Promise<void>;
};

export async function buildDeps(config: AppConfig): Promise<AppDeps> {
  const db = createDb(config.databaseUrl);

  // Redis is mandatory (dev + prod)
  const redis = await RedisCache.connect(config.redisUrl);

  const tokenHasher: TokenHasher = new Sha256TokenHasher();
  const passwordHasher: PasswordHasher = new BcryptPasswordHasher({
    cost: config.bcryptCost,
  });

  const rateLimiter = new RateLimiter(redis, { prefix: 'rl' });

  return {
    db,
    cache: redis,
    rateLimiter,
    tokenHasher,
    passwordHasher,
    close: async () => {
      await redis.close();
      await db.destroy();
    },
  };
}
