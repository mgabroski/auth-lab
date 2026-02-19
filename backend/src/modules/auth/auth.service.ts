/**
 * backend/src/modules/auth/auth.service.ts
 *
 * WHY:
 * - Thin facade that dispatches to flow functions.
 *
 * RULES:
 * - No transactions here; flows own orchestration boundaries.
 * - No business logic here; flows/policies own logic.
 */

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

import type { TotpService } from '../../shared/security/totp';
import type { EncryptionService } from '../../shared/security/encryption';
import type { KeyedHasher } from '../../shared/security/keyed-hasher';

import type { AuthResult } from './auth.types';

import type { AuthRepo } from './dal/auth.repo';
import type { MfaRepo } from './dal/mfa.repo';

import type { RegisterParams } from './flows/register/execute-register-flow';
import { executeRegisterFlow } from './flows/register/execute-register-flow';

import type { LoginParams } from './flows/login/execute-login-flow';
import { executeLoginFlow } from './flows/login/execute-login-flow';

import type { RequestPasswordResetParams } from './flows/password-reset/request-password-reset-flow';
import { requestPasswordResetFlow } from './flows/password-reset/request-password-reset-flow';

import type { ResetPasswordParams } from './flows/password-reset/reset-password-flow';
import { resetPasswordFlow } from './flows/password-reset/reset-password-flow';

import { setupMfaFlow } from './flows/mfa/setup-mfa-flow';
import { verifyMfaSetupFlow } from './flows/mfa/verify-mfa-setup-flow';
import { verifyMfaFlow } from './flows/mfa/verify-mfa-flow';
import { recoverMfaFlow } from './flows/mfa/recover-mfa-flow';

export class AuthService {
  constructor(
    private readonly deps: {
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
      authRepo: AuthRepo;
      mfaRepo: MfaRepo;
      totpService: TotpService;
      encryptionService: EncryptionService;
      mfaKeyedHasher: KeyedHasher;
    },
  ) {}

  async register(params: RegisterParams): Promise<{ result: AuthResult; sessionId: string }> {
    return executeRegisterFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        passwordHasher: this.deps.passwordHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        queue: this.deps.queue,
        userRepo: this.deps.userRepo,
        membershipRepo: this.deps.membershipRepo,
        authRepo: this.deps.authRepo,
      },
      params,
    );
  }

  async login(params: LoginParams): Promise<{ result: AuthResult; sessionId: string }> {
    return executeLoginFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        passwordHasher: this.deps.passwordHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
      },
      params,
    );
  }

  async requestPasswordReset(params: RequestPasswordResetParams): Promise<void> {
    return requestPasswordResetFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        queue: this.deps.queue,
        authRepo: this.deps.authRepo,
      },
      params,
    );
  }

  async resetPassword(params: ResetPasswordParams): Promise<void> {
    return resetPasswordFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        passwordHasher: this.deps.passwordHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        authRepo: this.deps.authRepo,
      },
      params,
    );
  }

  async setupMfa(params: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    requestId: string;
    ip: string;
    userAgent: string | null;
  }): Promise<{ secret: string; qrCodeUri: string; recoveryCodes: string[] }> {
    return setupMfaFlow({
      deps: {
        db: this.deps.db,
        auditRepo: this.deps.auditRepo,
        mfaRepo: this.deps.mfaRepo,
        totpService: this.deps.totpService,
        encryptionService: this.deps.encryptionService,
        mfaKeyedHasher: this.deps.mfaKeyedHasher,
      },
      input: params,
    });
  }

  async verifyMfaSetup(params: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    code: string;
    requestId: string;
    ip: string;
    userAgent: string | null;
  }): Promise<{ status: 'AUTHENTICATED'; nextAction: 'NONE' }> {
    return verifyMfaSetupFlow({
      deps: {
        db: this.deps.db,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        mfaRepo: this.deps.mfaRepo,
        totpService: this.deps.totpService,
        encryptionService: this.deps.encryptionService,
      },
      input: params,
    });
  }

  async verifyMfa(params: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    mfaVerified: boolean;
    code: string;
    requestId: string;
    ip: string;
    userAgent: string | null;
  }): Promise<{ status: 'AUTHENTICATED'; nextAction: 'NONE' }> {
    return verifyMfaFlow({
      deps: {
        db: this.deps.db,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        rateLimiter: this.deps.rateLimiter,
        totpService: this.deps.totpService,
        encryptionService: this.deps.encryptionService,
      },
      input: params,
    });
  }

  async recoverMfa(params: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    mfaVerified: boolean;
    recoveryCode: string;
    requestId: string;
    ip: string;
    userAgent: string | null;
  }): Promise<{ status: 'AUTHENTICATED'; nextAction: 'NONE' }> {
    return recoverMfaFlow({
      deps: {
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        rateLimiter: this.deps.rateLimiter,
        mfaRepo: this.deps.mfaRepo,
        mfaKeyedHasher: this.deps.mfaKeyedHasher,
      },
      input: params,
    });
  }
}
