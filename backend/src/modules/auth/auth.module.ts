/**
 * backend/src/modules/auth/auth.module.ts
 *
 * WHY:
 * - Encapsulates Auth module wiring.
 * - DI creates infra; module composes domain units.
 * - Auth module owns register + login routes.
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
import type { UserRepo } from '../users/dal/user.repo';
import type { MembershipRepo } from '../memberships/dal/membership.repo';

import { AuthRepo } from './dal/auth.repo';
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
  userRepo: UserRepo;
  membershipRepo: MembershipRepo;
  isProduction: boolean;
}) {
  const authRepo = new AuthRepo(deps.db);

  const authService = new AuthService({
    db: deps.db,
    tokenHasher: deps.tokenHasher,
    passwordHasher: deps.passwordHasher,
    logger: deps.logger,
    rateLimiter: deps.rateLimiter,
    auditRepo: deps.auditRepo,
    sessionStore: deps.sessionStore,
    userRepo: deps.userRepo,
    membershipRepo: deps.membershipRepo,
    authRepo,
  });

  const controller = new AuthController(authService, deps.isProduction);

  return {
    authService,
    registerRoutes(app: FastifyInstance) {
      registerAuthRoutes(app, controller);
    },
  };
}
