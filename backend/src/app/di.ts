/**
 * src/app/di.ts
 *
 * WHY:
 * - Single dependency graph for the whole app.
 * - Creates infra clients ONCE (db, redis) and shares them safely.
 * - Keeps modules testable (later we can inject fakes).
 *
 * RULES:
 * - No business logic here.
 * - No HTTP logic here.
 * - Environment-dependent decisions (e.g. disable rate limits in test) belong HERE,
 *   not inside the classes themselves (DIP).
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
import { SessionStore } from '../shared/session/session.store';

import { InMemQueue } from '../shared/messaging/inmem-queue';
import type { Queue } from '../shared/messaging/queue';

// Brick 9 (MFA)
import { TotpService } from '../shared/security/totp';
import { EncryptionService } from '../shared/security/encryption';
import { HmacSha256KeyedHasher } from '../shared/security/keyed-hasher';
import type { KeyedHasher } from '../shared/security/keyed-hasher';

import { createTenantModule } from '../modules/tenants/tenant.module';
import type { TenantModule } from '../modules/tenants/tenant.module';

import { createInviteModule } from '../modules/invites/invite.module';
import type { InviteModule } from '../modules/invites/invite.module';

import { createUserModule } from '../modules/users/user.module';
import type { UserModule } from '../modules/users/user.module';

import { createMembershipModule } from '../modules/memberships/membership.module';
import type { MembershipModule } from '../modules/memberships/membership.module';

import { createAuthModule } from '../modules/auth/auth.module';
import type { AuthModule } from '../modules/auth/auth.module';

export type AppDeps = {
  db: ReturnType<typeof createDb>;
  cache: Cache;

  logger: Logger;

  rateLimiter: RateLimiter;
  tokenHasher: TokenHasher;
  passwordHasher: PasswordHasher;

  auditRepo: AuditRepo;
  sessionStore: SessionStore;

  totpService: TotpService;
  encryptionService: EncryptionService;
  mfaKeyedHasher: KeyedHasher;

  // messaging
  queue: Queue;

  // modules
  tenants: TenantModule;
  invites: InviteModule;
  users: UserModule;
  memberships: MembershipModule;
  auth: AuthModule;

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

  // Composition root decides when rate limiting is disabled.
  // The RateLimiter class itself has no knowledge of environments.
  const rateLimiter = new RateLimiter(redis, {
    prefix: 'rl',
    disabled: config.nodeEnv === 'test',
  });

  // shared repos / stores
  const auditRepo = new AuditRepo(db);
  const sessionStore = new SessionStore(redis, config.sessionTtlSeconds);

  // Brick 9 (MFA)
  const totpService = new TotpService(config.mfa.issuer);
  const encryptionService = new EncryptionService(config.mfa.encryptionKeyBase64);
  const mfaKeyedHasher: KeyedHasher = new HmacSha256KeyedHasher(config.mfa.hmacKeyBase64);

  // Phase 1: in-memory queue (swap for SQS/SendGrid adapter here in production)
  const queue: Queue = new InMemQueue();

  // modules (no HTTP / no business logic here)
  const tenants = createTenantModule({ db });
  const invites = createInviteModule({ db, tokenHasher, logger, auditRepo });
  const users = createUserModule({ db });
  const memberships = createMembershipModule({ db });

  const auth = createAuthModule({
    db,
    tokenHasher,
    passwordHasher,
    logger,
    rateLimiter,
    auditRepo,
    sessionStore,
    queue,
    userRepo: users.userRepo,
    membershipRepo: memberships.membershipRepo,
    isProduction: config.nodeEnv === 'production',
    totpService,
    encryptionService,
    mfaKeyedHasher,
  });

  return {
    db,
    cache: redis,
    logger,
    rateLimiter,
    tokenHasher,
    passwordHasher,
    auditRepo,
    sessionStore,

    // Brick 9 (MFA)
    totpService,
    encryptionService,
    mfaKeyedHasher,

    queue,
    tenants,
    invites,
    users,
    memberships,
    auth,
    close: async () => {
      await redis.close();
      await db.destroy();
    },
  };
}
