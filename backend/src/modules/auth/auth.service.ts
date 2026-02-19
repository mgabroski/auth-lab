/**
 * src/modules/auth/auth.service.ts
 *
 * WHY:
 * - Orchestrates password registration (7b), login (7c), and password reset (8).
 * - Brick 9 adds MFA setup + verification + recovery flows (TOTP).
 * - Only place in the auth module allowed to start transactions.
 *
 * RULES:
 * - No raw DB access outside queries/DAL.
 * - Enforce tenant safety.
 * - Never store/log raw passwords or tokens.
 * - Audit meaningful actions via AuditWriter (progressive context enrichment).
 * - Rate limit at the start of each flow (before any DB work).
 *
 * STRUCTURE:
 * - register(): slim orchestrator — calls helpers for each distinct responsibility.
 * - login(): keeps credential/membership checks inline because the two-phase audit
 *   pattern (success inside tx, failure outside tx) would become MORE complex if
 *   those checks were extracted — the failure context must be built progressively
 *   as each check fails, and the catch block needs it to survive the rollback.
 * - requestPasswordReset(): always returns the same response regardless of outcome.
 *   Anti-enumeration: user-not-found and SSO-only paths are silent.
 * - resetPassword(): consumes token, updates password, destroys all sessions.
 *   No auto-login after reset — user must prove new credentials by signing in.
 *
 * LOGIN / RESET AUDIT PATTERNS:
 * - Success audits inside transaction (committed atomically).
 * - Failure audits outside transaction (survive rollback).
 * - Password reset requested audit written on ALL paths (admin visibility).
 */

import type { DbExecutor } from '../../shared/db/db';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { PasswordHasher } from '../../shared/security/password-hasher';
import type { Logger } from '../../shared/logger/logger';
import type { RateLimiter } from '../../shared/security/rate-limit';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import type { SessionStore } from '../../shared/session/session.store';
import type { Queue } from '../../shared/messaging/queue';
import type { TotpService } from '../../shared/security/totp';
import type { EncryptionService } from '../../shared/security/encryption';
import type { KeyedHasher } from '../../shared/security/keyed-hasher';
import type { UserRepo } from '../users/dal/user.repo';
import type { MembershipRepo } from '../memberships/dal/membership.repo';
import type { AuthRepo } from './dal/auth.repo';
import type { MfaRepo } from './dal/mfa.repo';
import type { AuthResult } from './auth.types';
import { executeLoginFlow } from './flows/login/execute-login-flow';
import { executeRegisterFlow } from './flows/register/execute-register-flow';
import { requestPasswordResetFlow } from './flows/password-reset/request-password-reset-flow';
import { resetPasswordFlow } from './flows/password-reset/reset-password-flow';
import { setupMfaFlow } from './flows/mfa/setup-mfa-flow';
import { verifyMfaSetupFlow } from './flows/mfa/verify-mfa-setup-flow';
import { verifyMfaFlow } from './flows/mfa/verify-mfa-flow';
import { recoverMfaFlow } from './flows/mfa/recover-mfa-flow';

export type RegisterParams = {
  tenantKey: string | null;
  email: string;
  password: string;
  name: string;
  inviteToken: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export type LoginParams = {
  tenantKey: string | null;
  email: string;
  password: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export type RequestPasswordResetParams = {
  tenantKey: string | null;
  email: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

export type ResetPasswordParams = {
  tenantKey: string | null;
  token: string;
  newPassword: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

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
      mfaRecoveryCodesCount: number;
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
        mfaRecoveryCodesCount: this.deps.mfaRecoveryCodesCount,
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
