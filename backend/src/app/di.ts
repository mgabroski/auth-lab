/**
 * backend/src/app/di.ts
 *
 * WHY:
 * - Single dependency graph for the whole app.
 * - Creates infra clients ONCE (db, redis) and shares them safely.
 * - Keeps modules testable (later we can inject fakes).
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

import { logger } from '../shared/logger/logger';
import type { Logger } from '../shared/logger/logger';

import { AuditRepo } from '../shared/audit/audit.repo';

import { createTenantModule } from '../modules/tenants/tenant.module';
import type { TenantModule } from '../modules/tenants/tenant.module';

import { createInviteModule } from '../modules/invites/invite.module';
import type { InviteModule } from '../modules/invites/invite.module';

export type AppDeps = {
  db: ReturnType<typeof createDb>;
  cache: Cache;

  logger: Logger;

  rateLimiter: RateLimiter;
  tokenHasher: TokenHasher;
  passwordHasher: PasswordHasher;

  // shared repos
  auditRepo: AuditRepo;

  // modules
  tenants: TenantModule;
  invites: InviteModule;

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

  // shared repos
  const auditRepo = new AuditRepo(db);

  // modules (no HTTP / no business logic here)
  const tenants = createTenantModule({ db });
  const invites = createInviteModule({ db, tokenHasher, logger, auditRepo });

  return {
    db,
    cache: redis,
    logger,
    rateLimiter,
    tokenHasher,
    passwordHasher,
    auditRepo,
    tenants,
    invites,
    close: async () => {
      await redis.close();
      await db.destroy();
    },
  };
}
