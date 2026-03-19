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
 * - EmailAdapter selection is driven by config.email.provider.
 * - NoopEmailAdapter is rejected at startup when NODE_ENV=production.
 *   This is the production guard: if someone deploys without configuring
 *   EMAIL_PROVIDER=smtp, the process crashes immediately with a clear error
 *   rather than silently swallowing all email delivery.
 * - Avoid `any` and unsafe casts; validate + narrow config at boundaries.
 *
 * 9/10 HARDENING:
 * - Added SmtpEmailAdapter wiring based on config.email.provider.
 * - Added production guard: NoopEmailAdapter is not allowed when nodeEnv=production.
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

import { TotpService } from '../shared/security/totp';
import { EncryptionService } from '../shared/security/encryption';
import { HmacSha256KeyedHasher } from '../shared/security/keyed-hasher';
import type { KeyedHasher } from '../shared/security/keyed-hasher';

import { OutboxRepo } from '../shared/outbox/outbox.repo';
import {
  OutboxEncryption,
  type OutboxEncVersion,
  type OutboxEncryptionConfig,
} from '../shared/outbox/outbox-encryption';
import type { EmailAdapter } from '../shared/outbox/email.adapter';
import { NoopEmailAdapter } from '../shared/outbox/noop-email.adapter';
import { SmtpEmailAdapter } from '../shared/outbox/smtp-email.adapter';

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
import { LocalOidcSsoAdapter } from '../modules/auth/sso/local-oidc/local-oidc-sso.adapter';

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

  outboxRepo: OutboxRepo;
  outboxEncryption: OutboxEncryption;
  emailAdapter: EmailAdapter;

  tenants: TenantModule;
  invites: InviteModule;
  users: UserModule;
  memberships: MembershipModule;
  auth: AuthModule;
  audit: AuditModule;

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

/**
 * Builds the email adapter based on config.email.provider.
 *
 * PRODUCTION GUARD:
 * NoopEmailAdapter in production would silently swallow every invite,
 * password reset, and verification email. The process fails immediately
 * with a clear error rather than allowing a silent production misconfiguration.
 */
function buildEmailAdapter(
  config: AppConfig,
  deps: { logger: Logger; tokenHasher: TokenHasher },
): EmailAdapter {
  if (config.email.provider === 'smtp') {
    if (!config.email.smtp) {
      throw new Error(
        'Config: EMAIL_PROVIDER=smtp requires SMTP_HOST and SMTP_FROM to be configured',
      );
    }

    return new SmtpEmailAdapter(config.email.smtp, deps);
  }

  // NoopEmailAdapter — acceptable in development and test environments.
  // NEVER acceptable in production.
  if (config.nodeEnv === 'production') {
    throw new Error(
      [
        'PRODUCTION STARTUP GUARD: EMAIL_PROVIDER=noop is not allowed in production.',
        'Set EMAIL_PROVIDER=smtp and configure SMTP_HOST, SMTP_FROM, and SMTP_PORT.',
        'If you are using AWS SES, set SMTP_HOST=email-smtp.<region>.amazonaws.com',
        'and SMTP_USER/SMTP_PASS to your SES SMTP credentials.',
      ].join('\n'),
    );
  }

  return new NoopEmailAdapter(deps);
}

export async function buildDeps(
  config: AppConfig,
  overrides: BuildDepsOverrides = {},
): Promise<AppDeps> {
  const db = createDb(config.databaseUrl);

  const redis = await RedisCache.connect(config.redisUrl);

  const tokenHasher: TokenHasher = new Sha256TokenHasher();
  const passwordHasher: PasswordHasher = new BcryptPasswordHasher({
    cost: config.bcryptCost,
  });

  const rateLimiter = new RateLimiter(redis, {
    prefix: 'rl',
    disabled: config.nodeEnv === 'test',
  });

  const auditRepo = new AuditRepo(db);
  const sessionStore = new SessionStore(redis, config.sessionTtlSeconds, tokenHasher);

  const totpService = new TotpService(config.mfa.issuer);
  const encryptionService = new EncryptionService(config.mfa.encryptionKeyBase64);
  const mfaKeyedHasher: KeyedHasher = new HmacSha256KeyedHasher(config.mfa.hmacKeyBase64);

  const ssoStateEncryptionService = new EncryptionService(config.sso.stateEncryptionKeyBase64);

  const ssoProviderRegistry =
    overrides.ssoProviderRegistry ??
    (() => {
      const registry = new SsoProviderRegistry();

      // CI-only: when LOCAL_OIDC_ENABLED=true, the local OIDC server
      // (infra/oidc-server/) is used for both SSO provider slots.
      // This proves the real jose jwtVerify() cryptographic path
      // (JWKS HTTP fetch → RSA-256 signature → iss/aud/exp → nonce)
      // in CI without real Google/Microsoft credentials.
      // In production and staging, config.sso.localOidc is always undefined.
      if (config.sso.localOidc) {
        const { issuerUrl, clientId } = config.sso.localOidc;
        return registry
          .register(new LocalOidcSsoAdapter({ providerKey: 'google', issuerUrl, clientId }))
          .register(new LocalOidcSsoAdapter({ providerKey: 'microsoft', issuerUrl, clientId }));
      }

      return registry
        .register(new GoogleSsoAdapter(config.sso.googleClientId, config.sso.googleClientSecret))
        .register(
          new MicrosoftSsoAdapter(config.sso.microsoftClientId, config.sso.microsoftClientSecret),
        );
    })();

  const outboxRepo = new OutboxRepo(db);
  const outboxEncryption = new OutboxEncryption(buildOutboxEncryptionConfig(config));

  // Build email adapter with production guard.
  const emailAdapter = buildEmailAdapter(config, { logger, tokenHasher });

  const tenants = createTenantModule({ db });

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
