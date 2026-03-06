/**
 * src/modules/auth/auth.module.ts
 *
 * WHY:
 * - Encapsulates Auth module wiring.
 * - DI creates infra; module composes domain units.
 *
 * RULES:
 * - No infra creation here (DI passes deps in).
 * - No globals/singletons here.
 */

import type { FastifyInstance } from 'fastify';
import type { DbExecutor } from '../../shared/db/db';
import type { Cache } from '../../shared/cache/cache';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { PasswordHasher } from '../../shared/security/password-hasher';
import type { Logger } from '../../shared/logger/logger';
import type { RateLimiter } from '../../shared/security/rate-limit';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import type { SessionStore } from '../../shared/session/session.store';
import type { UserRepo } from '../users/dal/user.repo';
import type { MembershipRepo } from '../memberships/dal/membership.repo';

import type { TotpService } from '../../shared/security/totp';
import type { EncryptionService } from '../../shared/security/encryption';
import type { KeyedHasher } from '../../shared/security/keyed-hasher';
import type { SsoProviderRegistry } from './sso/sso-provider-registry';

import type { OutboxRepo } from '../../shared/outbox/outbox.repo';
import type { OutboxEncryption } from '../../shared/outbox/outbox-encryption';

import { AuthRepo } from './dal/auth.repo';
import { MfaRepo } from './dal/mfa.repo';
import { EmailVerificationRepo } from './dal/email-verification.repo';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { registerAuthRoutes } from './auth.routes';

export type AuthModule = ReturnType<typeof createAuthModule>;

export function createAuthModule(deps: {
  db: DbExecutor;
  cache: Cache;
  tokenHasher: TokenHasher;
  passwordHasher: PasswordHasher;
  logger: Logger;
  rateLimiter: RateLimiter;
  auditRepo: AuditRepo;
  sessionStore: SessionStore;
  userRepo: UserRepo;
  membershipRepo: MembershipRepo;

  outboxRepo: OutboxRepo;
  outboxEncryption: OutboxEncryption;

  isProduction: boolean;
  sessionTtlSeconds: number;

  totpService: TotpService;
  encryptionService: EncryptionService;
  mfaKeyedHasher: KeyedHasher;

  sso: {
    stateEncryptionService: EncryptionService;
    redirectBaseUrl: string;
    providerRegistry: SsoProviderRegistry;
  };
}) {
  const authRepo = new AuthRepo(deps.db);
  const mfaRepo = new MfaRepo(deps.db);
  const emailVerificationRepo = new EmailVerificationRepo(deps.db);

  const authService = new AuthService({
    db: deps.db,
    cache: deps.cache,
    tokenHasher: deps.tokenHasher,
    passwordHasher: deps.passwordHasher,
    logger: deps.logger,
    rateLimiter: deps.rateLimiter,
    auditRepo: deps.auditRepo,
    sessionStore: deps.sessionStore,
    userRepo: deps.userRepo,
    membershipRepo: deps.membershipRepo,
    authRepo,
    mfaRepo,
    emailVerificationRepo,
    totpService: deps.totpService,
    encryptionService: deps.encryptionService,
    mfaKeyedHasher: deps.mfaKeyedHasher,
    outboxRepo: deps.outboxRepo,
    outboxEncryption: deps.outboxEncryption,
    sso: deps.sso,
  });

  const controller = new AuthController(authService, deps.isProduction, deps.sessionTtlSeconds);

  return {
    authService,
    registerRoutes(app: FastifyInstance) {
      registerAuthRoutes(app, controller);
    },
  };
}
