/**
 * src/modules/auth/auth.service.ts
 *
 * WHY:
 * - Orchestrates password registration (7b), login (7c), and password reset (8).
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

import type { UserRepo } from '../users/dal/user.repo';
import type { MembershipRepo } from '../memberships/dal/membership.repo';

import type { AuthRepo } from './dal/auth.repo';
import { AuthErrors } from './auth.errors';
import type { AuthResult } from './auth.types';

import {
  auditLoginSuccess,
  auditLoginFailed,
  auditPasswordResetRequested,
  auditPasswordResetCompleted,
} from './auth.audit';

import { resolveTenantForAuth } from './helpers/resolve-tenant-for-auth';
import { validateInviteForRegister } from './helpers/validate-invite-for-register';
import { ensurePasswordIdentity } from './helpers/ensure-password-identity';
import { provisionUserToTenant } from '../_shared/use-cases/provision-user-to-tenant.usecase';
import { writeRegisterAudits } from './helpers/write-register-audits';
import { createAuthSession } from './helpers/create-auth-session';
import { buildAuthResult } from './helpers/build-auth-result';

import { getUserByEmail, getUserById } from '../users/user.queries';
import { getMembershipByTenantAndUser } from '../memberships/membership.queries';
import { getPasswordIdentityWithHash, hasAuthIdentity, getValidResetToken } from './auth.queries';
import type { Tenant } from '../tenants/tenant.types';

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

// Password reset token TTL: 1 hour
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000;

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
    },
  ) {}

  // ── Register (Brick 7b) ──────────────────────────────────

  async register(params: RegisterParams): Promise<{ result: AuthResult; sessionId: string }> {
    const email = params.email.toLowerCase();
    const now = new Date();

    this.deps.logger.info({
      msg: 'auth.register.start',
      flow: 'auth.register',
      requestId: params.requestId,
      tenantKey: params.tenantKey,
      email,
    });

    await this.deps.rateLimiter.hitOrThrow({
      key: `register:email:${email}`,
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

    const { sessionId, nextAction } = await createAuthSession({
      sessionStore: this.deps.sessionStore,
      userId: user.id,
      tenantId: tenant.id,
      tenantKey: tenant.key,
      membershipId: membership.id,
      role: membership.role,
      tenant,
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

    this.deps.logger.info({
      msg: 'auth.login.start',
      flow: 'auth.login',
      requestId: params.requestId,
      tenantKey: params.tenantKey,
    });

    await this.deps.rateLimiter.hitOrThrow({
      key: `login:email:${email}`,
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

    const { sessionId, nextAction } = await createAuthSession({
      sessionStore: this.deps.sessionStore,
      userId: user.id,
      tenantId: tenant.id,
      tenantKey: tenant.key,
      membershipId: membership.id,
      role: membership.role,
      tenant,
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

    // Base audit writer — no tenant/user context yet (we may not find them)
    const audit = new AuditWriter(this.deps.auditRepo, {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    });

    // ── 1. Silent rate limit ─────────────────────────────────
    // hitOrSkip returns false (over limit) without throwing.
    // The response to the caller is always 200 — never reveal rate limit status.
    const withinLimit = await this.deps.rateLimiter.hitOrSkip({
      key: `forgot:email:${email}`,
      ...FORGOT_PASSWORD_LIMIT_PER_EMAIL,
    });

    if (!withinLimit) {
      await auditPasswordResetRequested(audit, { outcome: 'rate_limited' });
      return; // silent — caller returns 200 regardless
    }

    // ── 2. Find user ─────────────────────────────────────────
    const user = await getUserByEmail(this.deps.db, email);
    if (!user) {
      await auditPasswordResetRequested(audit, { outcome: 'user_not_found' });
      return; // silent — never reveal whether the email exists
    }

    // ── 3. Check for password identity ──────────────────────
    // SSO-only users have no password to reset.
    const hasPassword = await hasAuthIdentity(this.deps.db, {
      userId: user.id,
      provider: 'password',
    });
    if (!hasPassword) {
      await auditPasswordResetRequested(audit.withContext({ userId: user.id }), {
        outcome: 'sso_only',
      });
      return; // silent — never reveal the reason
    }

    // ── 4. Invalidate any existing active tokens ─────────────
    // Enforces one-active-token-at-a-time.
    // TRADEOFF: see comment in AuthRepo.invalidateActiveResetTokensForUser.
    await this.deps.authRepo.invalidateActiveResetTokensForUser({ userId: user.id });

    // ── 5. Generate and store new token ─────────────────────
    const rawToken = generateSecureToken(); // 32 random bytes, base64url
    const tokenHash = this.deps.tokenHasher.hash(rawToken);
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS);

    await this.deps.authRepo.insertPasswordResetToken({
      userId: user.id,
      tokenHash,
      expiresAt,
    });

    // ── 6. Enqueue reset email ───────────────────────────────
    // tenantKey is included so the email renderer can build the correct
    // tenant-scoped reset URL without querying the database.
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
    // ── 1. Hard rate limit ───────────────────────────────────
    await this.deps.rateLimiter.hitOrThrow({
      key: `reset:ip:${params.ip}`,
      ...RESET_PASSWORD_LIMIT_PER_IP,
    });

    // ── 2. Hash token and find valid record ──────────────────
    const tokenHash = this.deps.tokenHasher.hash(params.token);
    const resetToken = await getValidResetToken(this.deps.db, tokenHash);

    if (!resetToken) {
      throw AuthErrors.resetTokenInvalid();
    }

    // ── 3. Verify user still exists ─────────────────────────
    const user = await getUserById(this.deps.db, resetToken.userId);
    if (!user) {
      // Defensive: user deleted after token was issued
      throw AuthErrors.resetTokenInvalid();
    }

    // ── 4. Verify password identity still exists ─────────────
    // Defensive: user may have switched to SSO-only after requesting reset
    const hasPassword = await hasAuthIdentity(this.deps.db, {
      userId: user.id,
      provider: 'password',
    });
    if (!hasPassword) {
      throw AuthErrors.resetTokenInvalid();
    }

    // ── 5. Hash new password BEFORE opening the transaction ──
    // bcrypt is a slow CPU operation. Never hold a DB connection open during
    // CPU-heavy work — it wastes a connection from the pool for no reason.
    // The hash is derived from the raw password synchronously and does not
    // depend on any DB state, so it is safe to compute outside the transaction.
    const newHash = await this.deps.passwordHasher.hash(params.newPassword);

    // ── 6. Atomically update password + consume token ────────
    // WHY a transaction here:
    // updatePasswordHash + markResetTokenUsed + invalidateActiveResetTokensForUser
    // must succeed or fail together. Without a transaction, a crash between writes
    // could leave the DB in a partial state — e.g. password updated but token not
    // consumed, which would allow the same reset link to be used again.
    await this.deps.db.transaction().execute(async (trx) => {
      const authRepo = this.deps.authRepo.withDb(trx);

      // 6a. Update the password hash in auth_identities
      await authRepo.updatePasswordHash({
        userId: user.id,
        newHash,
      });

      // 6b. Consume this specific token (mark used_at = now())
      await authRepo.markResetTokenUsed({ tokenHash });

      // 6c. Invalidate any remaining active tokens for this user.
      // Handles the case where the user clicked "resend" multiple times before
      // resetting — only the token they just used is consumed by 6b, but any
      // older tokens from earlier "resend" clicks would still be active.
      // After a successful password reset those stale links must not work.
      await authRepo.invalidateActiveResetTokensForUser({ userId: user.id });
    });

    // ── 7. Destroy ALL sessions for this user ────────────────
    // Runs outside the DB transaction (Redis, not Postgres).
    // An attacker who had the old password must not retain access via
    // existing session cookies after the credential change.
    await this.deps.sessionStore.destroyAllForUser(user.id);

    // ── 8. Audit ─────────────────────────────────────────────
    // Also outside the transaction — audit writer uses the main db connection,
    // not the committed trx handle.
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

    // No session created — user must sign in again with the new password.
  }
}
