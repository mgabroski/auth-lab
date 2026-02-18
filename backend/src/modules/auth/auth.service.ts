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
import { AuditWriter } from '../../shared/audit/audit.writer';
import type { SessionStore } from '../../shared/session/session.store';
import type { Queue } from '../../shared/messaging/queue';
import { AppError } from '../../shared/http/errors';

// Brick 9 (MFA deps)
import type { TotpService } from '../../shared/security/totp';
import type { EncryptionService } from '../../shared/security/encryption';
import type { KeyedHasher } from '../../shared/security/keyed-hasher';

import type { UserRepo } from '../users/dal/user.repo';
import type { MembershipRepo } from '../memberships/dal/membership.repo';

import type { AuthRepo } from './dal/auth.repo';
import type { MfaRepo } from './dal/mfa.repo';

import { AuthErrors } from './auth.errors';
import type { AuthResult } from './auth.types';

import {
  auditPasswordResetCompleted,
  auditMfaSetupStarted,
  auditMfaSetupCompleted,
  auditMfaVerifySuccess,
  auditMfaVerifyFailed,
  auditMfaRecoveryUsed,
} from './auth.audit';

import { getUserById } from '../users/queries/user.queries';
import { hasAuthIdentity, getValidResetToken } from './queries/auth.queries';
import { getMfaSecretForUser } from './queries/mfa.queries';
import { executeLoginFlow } from './flows/login/execute-login-flow';
import { executeRegisterFlow } from './flows/register/execute-register-flow';
import { requestPasswordResetFlow } from './flows/password-reset/request-password-reset-flow';

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

const RESET_PASSWORD_LIMIT_PER_IP = { limit: 5, windowSeconds: 900 }; // hard 429

// Brick 9 (MFA) rate limits (global per-user)
const MFA_VERIFY_LIMIT_PER_USER = { limit: 5, windowSeconds: 900 }; // hard 429
const MFA_RECOVERY_LIMIT_PER_USER = { limit: 5, windowSeconds: 900 }; // hard 429

// Brick 9 (MFA) recovery codes
const RECOVERY_CODE_LENGTH = 16;
const RECOVERY_CODE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

const MfaErrors = {
  alreadyConfigured(): Error {
    // 409
    return AppError.conflict('MFA is already configured.');
  },
  noSetupInProgress(): Error {
    // 409
    return AppError.conflict('No MFA setup in progress.');
  },
  invalidCode(): Error {
    // 401 (authenticated but invalid MFA code)
    return AppError.unauthorized('Invalid code. Please try again.');
  },
  invalidRecoveryCode(): Error {
    // 401
    return AppError.unauthorized('Invalid recovery code.');
  },
  mfaNotConfigured(): Error {
    // 409 (they tried to verify/recover without a verified secret)
    return AppError.conflict('MFA is not configured.');
  },
  alreadyVerified(): Error {
    // 403 (authenticated but prohibited in this state)
    return AppError.forbidden('MFA is already verified for this session.');
  },
};

// ── Service ─────────────────────────────────────────────────

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

      // Brick 9 (MFA)
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

  // ── Reset Password (Brick 8) ─────────────────────────────

  async resetPassword(params: ResetPasswordParams): Promise<void> {
    await this.deps.rateLimiter.hitOrThrow({
      key: `reset:ip:${params.ip}`,
      ...RESET_PASSWORD_LIMIT_PER_IP,
    });

    const tokenHash = this.deps.tokenHasher.hash(params.token);
    const resetToken = await getValidResetToken(this.deps.db, tokenHash);

    if (!resetToken) {
      throw AuthErrors.resetTokenInvalid();
    }

    const user = await getUserById(this.deps.db, resetToken.userId);
    if (!user) {
      throw AuthErrors.resetTokenInvalid();
    }

    const hasPassword = await hasAuthIdentity(this.deps.db, {
      userId: user.id,
      provider: 'password',
    });
    if (!hasPassword) {
      throw AuthErrors.resetTokenInvalid();
    }

    const newHash = await this.deps.passwordHasher.hash(params.newPassword);

    await this.deps.db.transaction().execute(async (trx) => {
      const authRepo = this.deps.authRepo.withDb(trx);

      await authRepo.updatePasswordHash({
        userId: user.id,
        newHash,
      });

      await authRepo.markResetTokenUsed({ tokenHash });

      await authRepo.invalidateActiveResetTokensForUser({ userId: user.id });
    });

    await this.deps.sessionStore.destroyAllForUser(user.id);

    const audit = new AuditWriter(this.deps.auditRepo, {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    }).withContext({ userId: user.id });

    await auditPasswordResetCompleted(audit, { userId: user.id });

    this.deps.logger.info({
      msg: 'auth.password_reset.completed',
      flow: 'auth.reset-password',
      requestId: params.requestId,
      userId: user.id,
    });
  }

  // ── MFA Setup (Brick 9a) ─────────────────────────────────

  async setupMfa(params: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    requestId: string;
    ip: string;
    userAgent: string | null;
  }): Promise<{ secret: string; qrCodeUri: string; recoveryCodes: string[] }> {
    const audit = new AuditWriter(this.deps.auditRepo, {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    }).withContext({
      tenantId: params.tenantId,
      userId: params.userId,
      membershipId: params.membershipId,
    });

    const existing = await getMfaSecretForUser(this.deps.db, params.userId);
    if (existing?.isVerified) {
      throw MfaErrors.alreadyConfigured();
    }

    if (existing && !existing.isVerified) {
      await this.deps.mfaRepo.deleteUnverifiedMfaSecret({ userId: params.userId });
    }

    const plaintextSecret = this.deps.totpService.generateSecret();
    const secretEncrypted = this.deps.encryptionService.encrypt(plaintextSecret);

    await this.deps.mfaRepo.insertMfaSecret({
      userId: params.userId,
      secretEncrypted,
    });

    const { randomBytes } = await import('node:crypto');

    const recoveryCodes: string[] = [];
    for (let i = 0; i < this.deps.mfaRecoveryCodesCount; i++) {
      const bytes = randomBytes(RECOVERY_CODE_LENGTH);
      let code = '';
      for (let j = 0; j < RECOVERY_CODE_LENGTH; j++) {
        code += RECOVERY_CODE_CHARSET[bytes[j] % RECOVERY_CODE_CHARSET.length];
      }
      recoveryCodes.push(code);
    }

    const codeHashes = recoveryCodes.map((code) => this.deps.mfaKeyedHasher.hash(code));

    await this.deps.mfaRepo.insertRecoveryCodes({
      userId: params.userId,
      codeHashes,
    });

    const user = await getUserById(this.deps.db, params.userId);
    const label = user?.email ?? 'user';

    const qrCodeUri = this.deps.totpService.buildUri(plaintextSecret, label);

    await auditMfaSetupStarted(audit, { userId: params.userId });

    return { secret: plaintextSecret, qrCodeUri, recoveryCodes };
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
    const audit = new AuditWriter(this.deps.auditRepo, {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    }).withContext({
      tenantId: params.tenantId,
      userId: params.userId,
      membershipId: params.membershipId,
    });

    const secretRow = await getMfaSecretForUser(this.deps.db, params.userId);
    if (!secretRow || secretRow.isVerified) {
      throw MfaErrors.noSetupInProgress();
    }

    const plaintextSecret = this.deps.encryptionService.decrypt(secretRow.secretEncrypted);
    const ok = this.deps.totpService.verify(plaintextSecret, params.code);
    if (!ok) {
      await auditMfaVerifyFailed(audit, { userId: params.userId });
      throw MfaErrors.invalidCode();
    }

    await this.deps.mfaRepo.verifyMfaSecret({ userId: params.userId });
    await this.deps.sessionStore.updateSession(params.sessionId, { mfaVerified: true });

    await auditMfaSetupCompleted(audit, { userId: params.userId });

    return { status: 'AUTHENTICATED', nextAction: 'NONE' };
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
    if (params.mfaVerified) {
      throw MfaErrors.alreadyVerified();
    }

    await this.deps.rateLimiter.hitOrThrow({
      key: `mfa:verify:user:${params.userId}`,
      ...MFA_VERIFY_LIMIT_PER_USER,
    });

    const audit = new AuditWriter(this.deps.auditRepo, {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    }).withContext({
      tenantId: params.tenantId,
      userId: params.userId,
      membershipId: params.membershipId,
    });

    const secretRow = await getMfaSecretForUser(this.deps.db, params.userId);
    if (!secretRow || !secretRow.isVerified) {
      throw MfaErrors.mfaNotConfigured();
    }

    const plaintextSecret = this.deps.encryptionService.decrypt(secretRow.secretEncrypted);
    const ok = this.deps.totpService.verify(plaintextSecret, params.code);

    if (!ok) {
      await auditMfaVerifyFailed(audit, { userId: params.userId });
      throw MfaErrors.invalidCode();
    }

    await this.deps.sessionStore.updateSession(params.sessionId, { mfaVerified: true });
    await auditMfaVerifySuccess(audit, { userId: params.userId });

    return { status: 'AUTHENTICATED', nextAction: 'NONE' };
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
    if (params.mfaVerified) {
      throw MfaErrors.alreadyVerified();
    }

    await this.deps.rateLimiter.hitOrThrow({
      key: `mfa:recover:user:${params.userId}`,
      ...MFA_RECOVERY_LIMIT_PER_USER,
    });

    const audit = new AuditWriter(this.deps.auditRepo, {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    }).withContext({
      tenantId: params.tenantId,
      userId: params.userId,
      membershipId: params.membershipId,
    });

    const codeHash = this.deps.mfaKeyedHasher.hash(params.recoveryCode);

    const used = await this.deps.mfaRepo.useRecoveryCodeAtomic({
      userId: params.userId,
      codeHash,
    });

    if (!used) {
      throw MfaErrors.invalidRecoveryCode();
    }

    await this.deps.sessionStore.updateSession(params.sessionId, { mfaVerified: true });
    await auditMfaRecoveryUsed(audit, { userId: params.userId });

    return { status: 'AUTHENTICATED', nextAction: 'NONE' };
  }

  // ── Test helpers (never called in production paths) ──────────────────────

  /** @testOnly */
  generateTotpSecretForTest(): string {
    return this.deps.totpService.generateSecret();
  }

  /** @testOnly */
  encryptSecretForTest(secret: string): string {
    return this.deps.encryptionService.encrypt(secret);
  }

  /** @testOnly */
  generateTotpCodeForTest(plaintextSecret: string): string {
    return this.deps.totpService.generateCodeForTest(plaintextSecret);
  }

  /** @testOnly */
  hashRecoveryCodeForTest(code: string): string {
    return this.deps.mfaKeyedHasher.hash(code);
  }
}
