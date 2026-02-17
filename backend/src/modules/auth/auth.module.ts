/**
 * src/modules/auth/auth.module.ts
 *
 * WHY:
 * - Encapsulates Auth module wiring.
 * - DI creates infra; module composes domain units.
 * - Auth module owns register + login + forgot-password + reset-password + MFA routes.
 *
 * RULES:
 * - No infra creation here (DI passes deps in).
 * - No globals/singletons here.
 */

import type { FastifyInstance } from 'fastify';
import type { DbExecutor } from '../../shared/db/db';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { PasswordHasher } from '../../shared/security/password-hasher';
import type { Logger } from '../../shared/logger/logger';
import type { RateLimiter } from '../../shared/security/rate-limit';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import type { SessionStore } from '../../shared/session/session.store';
import type { Queue } from '../../shared/messaging/queue';
import type { UserRepo } from '../users/dal/user.repo';
import type { MembershipRepo } from '../memberships/dal/membership.repo';

// Brick 9 (MFA)
import type { TotpService } from '../../shared/security/totp';
import type { EncryptionService } from '../../shared/security/encryption';
import type { KeyedHasher } from '../../shared/security/keyed-hasher';

import { AuthRepo } from './dal/auth.repo';
import { MfaRepo } from './dal/mfa.repo';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { registerAuthRoutes } from './auth.routes';

export type AuthModule = ReturnType<typeof createAuthModule>;

export function createAuthModule(deps: {
  db: DbExecutor;
  tokenHasher: TokenHasher;
  passwordHasher: PasswordHasher;
  logger: Logger;
  rateLimiter: RateLimiter;
  auditRepo: AuditRepo;
  sessionStore: SessionStore;
  queue: Queue;
  userRepo: UserRepo;
  membershipRepo: MembershipRepo;
  isProduction: boolean;

  // Brick 9 (MFA)
  totpService: TotpService;
  encryptionService: EncryptionService;
  mfaKeyedHasher: KeyedHasher;
  mfaRecoveryCodesCount: number;
}) {
  const authRepo = new AuthRepo(deps.db);
  const mfaRepo = new MfaRepo(deps.db);

  const authService = new AuthService({
    db: deps.db,
    tokenHasher: deps.tokenHasher,
    passwordHasher: deps.passwordHasher,
    logger: deps.logger,
    rateLimiter: deps.rateLimiter,
    auditRepo: deps.auditRepo,
    sessionStore: deps.sessionStore,
    queue: deps.queue,
    userRepo: deps.userRepo,
    membershipRepo: deps.membershipRepo,
    authRepo,

    // Brick 9 (MFA)
    mfaRepo,
    totpService: deps.totpService,
    encryptionService: deps.encryptionService,
    mfaKeyedHasher: deps.mfaKeyedHasher,
    mfaRecoveryCodesCount: deps.mfaRecoveryCodesCount,
  });

  const controller = new AuthController(authService, deps.isProduction);

  return {
    authService,
    registerRoutes(app: FastifyInstance) {
      registerAuthRoutes(app, controller);
    },
  };
}
