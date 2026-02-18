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
import { generateSecureToken } from '../../shared/security/token';
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
  auditLoginSuccess,
  auditLoginFailed,
  auditPasswordResetRequested,
  auditPasswordResetCompleted,
  // Brick 9 (MFA audits)
  auditMfaSetupStarted,
  auditMfaSetupCompleted,
  auditMfaVerifySuccess,
  auditMfaVerifyFailed,
  auditMfaRecoveryUsed,
} from './auth.audit';

import { resolveTenantForAuth } from './helpers/resolve-tenant-for-auth';
import { validateInviteForRegister } from './helpers/validate-invite-for-register';
import { ensurePasswordIdentity } from './helpers/ensure-password-identity';
import { provisionUserToTenant } from '../_shared/use-cases/provision-user-to-tenant.usecase';
import { writeRegisterAudits } from './helpers/write-register-audits';
import { createAuthSession } from './helpers/create-auth-session';
import { buildAuthResult } from './helpers/build-auth-result';

import { getUserByEmail, getUserById } from '../users/queries/user.queries';
import { getMembershipByTenantAndUser } from '../memberships/membership.queries';
import { getPasswordIdentityWithHash, hasAuthIdentity, getValidResetToken } from './auth.queries';
import type { Tenant } from '../tenants/tenant.types';

// Brick 9 (MFA queries)
import { getMfaSecretForUser } from './mfa.queries';

// ── PII-safe helpers ─────────────────────────────────────────
// We avoid putting raw emails into infra keys (Redis) or operational logs.
// Audits may still include email where needed for admin/compliance.
function emailDomain(email: string): string {
  const at = email.lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1) : '';
}

// ── Params ──────────────────────────────────────────────────

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

// ── Rate-limit constants ────────────────────────────────────

const REGISTER_LIMIT_PER_EMAIL = { limit: 5, windowSeconds: 900 };
const REGISTER_LIMIT_PER_IP = { limit: 20, windowSeconds: 900 };
const LOGIN_LIMIT_PER_EMAIL = { limit: 5, windowSeconds: 900 };
const LOGIN_LIMIT_PER_IP = { limit: 20, windowSeconds: 900 };
const FORGOT_PASSWORD_LIMIT_PER_EMAIL = { limit: 3, windowSeconds: 3600 }; // silent
const RESET_PASSWORD_LIMIT_PER_IP = { limit: 5, windowSeconds: 900 }; // hard 429

// Brick 9 (MFA) rate limits (global per-user)
const MFA_VERIFY_LIMIT_PER_USER = { limit: 5, windowSeconds: 900 }; // hard 429
const MFA_RECOVERY_LIMIT_PER_USER = { limit: 5, windowSeconds: 900 }; // hard 429

// Password reset token TTL: 1 hour
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000;

// Brick 9 (MFA) recovery codes
const RECOVERY_CODE_LENGTH = 16;
const RECOVERY_CODE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

// ── Login failure context (for two-phase audit) ─────────────

type LoginFailureContext = {
  tenantId: string;
  userId?: string;
  membershipId?: string;
  email: string;
  reason: string;
  error: Error;
};

// ── Transaction result types ─────────────────────────────────

type LoginTxResult = {
  user: { id: string; email: string; name: string | null };
  membership: { id: string; role: 'ADMIN' | 'MEMBER'; status: 'ACTIVE' | 'INVITED' | 'SUSPENDED' };
  tenant: Tenant;
};

// ── Brick 9 (MFA) errors ────────────────────────────────────

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

  // ── Register (Brick 7b) ──────────────────────────────────

  async register(params: RegisterParams): Promise<{ result: AuthResult; sessionId: string }> {
    const email = params.email.toLowerCase();
    const emailKey = this.deps.tokenHasher.hash(email);
    const now = new Date();

    this.deps.logger.info({
      msg: 'auth.register.start',
      flow: 'auth.register',
      requestId: params.requestId,
      tenantKey: params.tenantKey,
      emailDomain: emailDomain(email),
      emailKey,
    });

    await this.deps.rateLimiter.hitOrThrow({
      key: `register:email:${emailKey}`,
      ...REGISTER_LIMIT_PER_EMAIL,
    });
    await this.deps.rateLimiter.hitOrThrow({
      key: `register:ip:${params.ip}`,
      ...REGISTER_LIMIT_PER_IP,
    });

    const { user, membership, tenant } = await this.deps.db.transaction().execute(async (trx) => {
      const userRepo = this.deps.userRepo.withDb(trx);
      const membershipRepo = this.deps.membershipRepo.withDb(trx);
      const authRepo = this.deps.authRepo.withDb(trx);

      const baseAudit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      });

      const tenant = await resolveTenantForAuth(trx, params.tenantKey);

      const invite = await validateInviteForRegister({
        trx,
        tokenHasher: this.deps.tokenHasher,
        tenantId: tenant.id,
        inviteToken: params.inviteToken,
        email,
      });

      const provisionResult = await provisionUserToTenant({
        trx,
        userRepo,
        membershipRepo,
        email,
        name: params.name,
        tenantId: tenant.id,
        role: invite.role,
        now,
      });

      await ensurePasswordIdentity({
        trx,
        authRepo,
        passwordHasher: this.deps.passwordHasher,
        userId: provisionResult.user.id,
        rawPassword: params.password,
      });

      const fullAudit = baseAudit.withContext({
        tenantId: tenant.id,
        userId: provisionResult.user.id,
        membershipId: provisionResult.membership.id,
      });

      await writeRegisterAudits(fullAudit, provisionResult);

      return { ...provisionResult, tenant };
    });

    // New user will never have MFA configured yet, but keep it explicit.
    const hasVerifiedMfaSecret = false;

    const { sessionId, nextAction } = await createAuthSession({
      sessionStore: this.deps.sessionStore,
      userId: user.id,
      tenantId: tenant.id,
      tenantKey: tenant.key,
      membershipId: membership.id,
      role: membership.role,
      tenant,
      hasVerifiedMfaSecret,
      now,
    });

    this.deps.logger.info({
      msg: 'auth.register.success',
      flow: 'auth.register',
      requestId: params.requestId,
      tenantId: tenant.id,
      userId: user.id,
      membershipId: membership.id,
      role: membership.role,
    });

    return {
      sessionId,
      result: buildAuthResult({ nextAction, user, membership }),
    };
  }

  // ── Login (Brick 7c) ─────────────────────────────────────

  async login(params: LoginParams): Promise<{ result: AuthResult; sessionId: string }> {
    const email = params.email.toLowerCase();
    const emailKey = this.deps.tokenHasher.hash(email);

    this.deps.logger.info({
      msg: 'auth.login.start',
      flow: 'auth.login',
      requestId: params.requestId,
      tenantKey: params.tenantKey,
      emailDomain: emailDomain(email),
      emailKey,
    });

    await this.deps.rateLimiter.hitOrThrow({
      key: `login:email:${emailKey}`,
      ...LOGIN_LIMIT_PER_EMAIL,
    });
    await this.deps.rateLimiter.hitOrThrow({
      key: `login:ip:${params.ip}`,
      ...LOGIN_LIMIT_PER_IP,
    });

    let failureCtx: LoginFailureContext | null = null;
    let txResult: LoginTxResult | null = null;

    try {
      txResult = await this.deps.db.transaction().execute(async (trx): Promise<LoginTxResult> => {
        const audit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
          requestId: params.requestId,
          ip: params.ip,
          userAgent: params.userAgent,
        });

        const tenant = await resolveTenantForAuth(trx, params.tenantKey);

        const user = await getUserByEmail(trx, email);
        if (!user) {
          failureCtx = {
            tenantId: tenant.id,
            email,
            reason: 'user_not_found',
            error: AuthErrors.invalidCredentials(),
          };
          throw failureCtx.error;
        }

        const passwordResult = await getPasswordIdentityWithHash(trx, user.id);
        if (!passwordResult) {
          failureCtx = {
            tenantId: tenant.id,
            userId: user.id,
            email,
            reason: 'no_password_identity',
            error: AuthErrors.invalidCredentials(),
          };
          throw failureCtx.error;
        }

        const passwordValid = await this.deps.passwordHasher.verify(
          params.password,
          passwordResult.passwordHash,
        );
        if (!passwordValid) {
          failureCtx = {
            tenantId: tenant.id,
            userId: user.id,
            email,
            reason: 'wrong_password',
            error: AuthErrors.invalidCredentials(),
          };
          throw failureCtx.error;
        }

        const membership = await getMembershipByTenantAndUser(trx, {
          tenantId: tenant.id,
          userId: user.id,
        });

        if (!membership) {
          failureCtx = {
            tenantId: tenant.id,
            userId: user.id,
            email,
            reason: 'no_membership',
            error: AuthErrors.noAccess(),
          };
          throw failureCtx.error;
        }

        if (membership.status === 'SUSPENDED') {
          failureCtx = {
            tenantId: tenant.id,
            userId: user.id,
            membershipId: membership.id,
            email,
            reason: 'suspended',
            error: AuthErrors.accountSuspended(),
          };
          throw failureCtx.error;
        }

        if (membership.status === 'INVITED') {
          failureCtx = {
            tenantId: tenant.id,
            userId: user.id,
            membershipId: membership.id,
            email,
            reason: 'invite_not_accepted',
            error: AuthErrors.inviteNotYetAccepted(),
          };
          throw failureCtx.error;
        }

        const fullAudit = audit
          .withContext({ tenantId: tenant.id })
          .withContext({ userId: user.id, membershipId: membership.id });

        await auditLoginSuccess(fullAudit, {
          userId: user.id,
          email: user.email,
          membershipId: membership.id,
          role: membership.role,
        });

        return {
          user: { id: user.id, email: user.email, name: user.name ?? null },
          membership: { id: membership.id, role: membership.role, status: membership.status },
          tenant,
        };
      });
    } catch (err) {
      if (failureCtx) {
        const ctx = failureCtx as LoginFailureContext;

        const failAudit = new AuditWriter(this.deps.auditRepo, {
          requestId: params.requestId,
          ip: params.ip,
          userAgent: params.userAgent,
        }).withContext({
          tenantId: ctx.tenantId,
          userId: ctx.userId ?? null,
          membershipId: ctx.membershipId ?? null,
        });

        await auditLoginFailed(failAudit, {
          email: ctx.email,
          reason: ctx.reason,
        });
      }

      throw err;
    }

    if (!txResult) {
      throw new Error('auth.login: transaction completed without result');
    }

    const { user, membership, tenant } = txResult;

    const mfaIsRequired = membership.role === 'ADMIN' || tenant.memberMfaRequired;

    const hasVerifiedMfaSecret = mfaIsRequired
      ? Boolean((await getMfaSecretForUser(this.deps.db, user.id))?.isVerified)
      : false;

    const { sessionId, nextAction } = await createAuthSession({
      sessionStore: this.deps.sessionStore,
      userId: user.id,
      tenantId: tenant.id,
      tenantKey: tenant.key,
      membershipId: membership.id,
      role: membership.role,
      tenant,
      hasVerifiedMfaSecret,
      now: new Date(),
    });

    this.deps.logger.info({
      msg: 'auth.login.success',
      flow: 'auth.login',
      requestId: params.requestId,
      tenantId: tenant.id,
      userId: user.id,
      membershipId: membership.id,
    });

    return {
      sessionId,
      result: buildAuthResult({ nextAction, user, membership }),
    };
  }

  // ── Forgot Password (Brick 8) ────────────────────────────

  async requestPasswordReset(params: RequestPasswordResetParams): Promise<void> {
    const email = params.email.toLowerCase();
    const emailKey = this.deps.tokenHasher.hash(email);

    // Base audit writer — no tenant/user context yet (we may not find them)
    const audit = new AuditWriter(this.deps.auditRepo, {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    });

    // ── 1. Silent rate limit ─────────────────────────────────
    const withinLimit = await this.deps.rateLimiter.hitOrSkip({
      key: `forgot:email:${emailKey}`,
      ...FORGOT_PASSWORD_LIMIT_PER_EMAIL,
    });

    if (!withinLimit) {
      await auditPasswordResetRequested(audit, { outcome: 'rate_limited' });
      return;
    }

    // ── 2. Find user ─────────────────────────────────────────
    const user = await getUserByEmail(this.deps.db, email);
    if (!user) {
      await auditPasswordResetRequested(audit, { outcome: 'user_not_found' });
      return;
    }

    // ── 3. Check for password identity ──────────────────────
    const hasPassword = await hasAuthIdentity(this.deps.db, {
      userId: user.id,
      provider: 'password',
    });
    if (!hasPassword) {
      await auditPasswordResetRequested(audit.withContext({ userId: user.id }), {
        outcome: 'sso_only',
      });
      return;
    }

    // ── 4. Invalidate any existing active tokens ─────────────
    await this.deps.authRepo.invalidateActiveResetTokensForUser({ userId: user.id });

    // ── 5. Generate and store new token ─────────────────────
    const rawToken = generateSecureToken();
    const tokenHash = this.deps.tokenHasher.hash(rawToken);
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);

    await this.deps.authRepo.insertPasswordResetToken({
      userId: user.id,
      tokenHash,
      expiresAt,
    });

    // ── 6. Enqueue reset email ───────────────────────────────
    await this.deps.queue.enqueue({
      type: 'auth.reset-password-email',
      userId: user.id,
      email,
      resetToken: rawToken,
      tenantKey: params.tenantKey ?? '',
    });

    // ── 7. Audit ─────────────────────────────────────────────
    await auditPasswordResetRequested(audit.withContext({ userId: user.id }), {
      outcome: 'sent',
    });
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
