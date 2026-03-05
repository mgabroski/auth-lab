/**
 * backend/src/app/di.ts
 *
 * WHY:
 * - Central dependency wiring for the application.
 * - Adds Outbox wiring (repo, encryption, email adapter).
 * - Keeps modules clean: flows depend on OutboxRepo + OutboxEncryption, not env.
 *
 * RULES:
 * - Worker start/stop is done in build-app (lifecycle), not in DI.
 * - EmailAdapter must be idempotent; NoopEmailAdapter is used in dev/test now.
 * - Avoid `any` and unsafe casts; validate + narrow config at boundaries.
 *
 * X8 UPDATE:
 * - Removed `queue` from createInviteModule() call — AdminInviteService no longer
 *   accepts Queue after the dead-code removal in admin-invite.service.ts.
 * - InMemQueue + Queue remain wired for createAuthModule() because auth.service.ts
 *   and execute-register-flow.ts still declare the Queue dep. Those usages are
 *   also dead (queue.enqueue is never called) but are out of scope for this commit.
 *   A follow-up can remove them from the auth module path once confirmed safe.
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

// Outbox (PR2)
import { OutboxRepo } from '../shared/outbox/outbox.repo';
import {
  OutboxEncryption,
  type OutboxEncVersion,
  type OutboxEncryptionConfig,
} from '../shared/outbox/outbox-encryption';
import type { EmailAdapter } from '../shared/outbox/email.adapter';
import { NoopEmailAdapter } from '../shared/outbox/noop-email.adapter';

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

import { createAuditModule } from '../modules/audit/audit.module';
import type { AuditModule } from '../modules/audit/audit.module';

import { SsoProviderRegistry } from '../modules/auth/sso/sso-provider-registry';
import { GoogleSsoAdapter } from '../modules/auth/sso/google/google-sso.adapter';
import { MicrosoftSsoAdapter } from '../modules/auth/sso/microsoft/microsoft-sso.adapter';

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

  ssoStateEncryptionService: EncryptionService;

  // messaging (legacy — still used by auth module path; see X8 note above)
  queue: Queue;

  // outbox
  outboxRepo: OutboxRepo;
  outboxEncryption: OutboxEncryption;
  emailAdapter: EmailAdapter;

  // modules
  tenants: TenantModule;
  invites: InviteModule;
  users: UserModule;
  memberships: MembershipModule;
  auth: AuthModule;
  audit: AuditModule;

  // lifecycle
  close: () => Promise<void>;
};

export type BuildDepsOverrides = {
  ssoProviderRegistry?: SsoProviderRegistry;
};

function isOutboxEncVersion(v: string): v is OutboxEncVersion {
  return /^v[0-9]+$/.test(v);
}

function buildOutboxEncryptionConfig(config: AppConfig): OutboxEncryptionConfig {
  const defaultVersionRaw = config.outbox.encDefaultVersion;
  if (!isOutboxEncVersion(defaultVersionRaw)) {
    throw new Error(
      `Config: OUTBOX_ENC_DEFAULT_VERSION must be like v1, v2; got "${defaultVersionRaw}"`,
    );
  }

  const keysByVersion: Record<OutboxEncVersion, string> = {} as Record<OutboxEncVersion, string>;

  for (const [k, val] of Object.entries(config.outbox.encKeysByVersion)) {
    if (!isOutboxEncVersion(k)) continue;
    keysByVersion[k] = val;
  }

  if (!keysByVersion[defaultVersionRaw]) {
    throw new Error(
      `Config: OUTBOX_ENC_DEFAULT_VERSION=${defaultVersionRaw} has no configured key in OUTBOX_ENC_KEY_*`,
    );
  }

  return {
    defaultVersion: defaultVersionRaw,
    keysByVersion,
  };
}

export async function buildDeps(
  config: AppConfig,
  overrides: BuildDepsOverrides = {},
): Promise<AppDeps> {
  const db = createDb(config.databaseUrl);

  // Redis is mandatory (dev + prod)
  const redis = await RedisCache.connect(config.redisUrl);

  const tokenHasher: TokenHasher = new Sha256TokenHasher();
  const passwordHasher: PasswordHasher = new BcryptPasswordHasher({
    cost: config.bcryptCost,
  });

  const rateLimiter = new RateLimiter(redis, {
    prefix: 'rl',
    disabled: config.nodeEnv === 'test',
  });

  // shared repos / stores
  const auditRepo = new AuditRepo(db);
  const sessionStore = new SessionStore(redis, config.sessionTtlSeconds, tokenHasher);

  // Brick 9 (MFA)
  const totpService = new TotpService(config.mfa.issuer);
  const encryptionService = new EncryptionService(config.mfa.encryptionKeyBase64);
  const mfaKeyedHasher: KeyedHasher = new HmacSha256KeyedHasher(config.mfa.hmacKeyBase64);

  // Brick 10 (SSO)
  const ssoStateEncryptionService = new EncryptionService(config.sso.stateEncryptionKeyBase64);

  const ssoProviderRegistry =
    overrides.ssoProviderRegistry ??
    new SsoProviderRegistry()
      .register(new GoogleSsoAdapter(config.sso.googleClientId, config.sso.googleClientSecret))
      .register(
        new MicrosoftSsoAdapter(config.sso.microsoftClientId, config.sso.microsoftClientSecret),
      );

  // Legacy queue — still referenced by auth module (execute-register-flow.ts).
  // Not used by invite module after X8.
  const queue: Queue = new InMemQueue();

  // Outbox
  const outboxRepo = new OutboxRepo(db);
  const outboxEncryption = new OutboxEncryption(buildOutboxEncryptionConfig(config));

  // Dev/test adapter by default (provider adapter swaps later via DI only)
  const emailAdapter: EmailAdapter = new NoopEmailAdapter({ logger, tokenHasher });

  // modules
  const tenants = createTenantModule({ db });

  // X8: queue removed from invite module — AdminInviteService no longer takes Queue.
  const invites = createInviteModule({
    db,
    tokenHasher,
    logger,
    auditRepo,
    rateLimiter,
    outboxRepo,
    outboxEncryption,
  });

  const users = createUserModule({ db });
  const memberships = createMembershipModule({ db });
  const audit = createAuditModule({ db });

  const auth = createAuthModule({
    db,
    cache: redis,
    tokenHasher,
    passwordHasher,
    logger,
    rateLimiter,
    auditRepo,
    sessionStore,
    queue,
    outboxRepo,
    outboxEncryption,
    userRepo: users.userRepo,
    membershipRepo: memberships.membershipRepo,
    isProduction: config.nodeEnv === 'production',
    sessionTtlSeconds: config.sessionTtlSeconds,
    totpService,
    encryptionService,
    mfaKeyedHasher,
    sso: {
      stateEncryptionService: ssoStateEncryptionService,
      redirectBaseUrl: config.sso.redirectBaseUrl,
      providerRegistry: ssoProviderRegistry,
    },
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

    totpService,
    encryptionService,
    mfaKeyedHasher,

    ssoStateEncryptionService,

    queue,

    outboxRepo,
    outboxEncryption,
    emailAdapter,

    tenants,
    invites,
    users,
    memberships,
    auth,
    audit,
    close: async () => {
      await redis.close();
      await db.destroy();
    },
  };
}
