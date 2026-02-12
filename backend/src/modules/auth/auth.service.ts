/**
 * backend/src/modules/auth/auth.service.ts
 *
 * WHY:
 * - Orchestrates password registration (7b) and login (7c) end-to-end.
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
 *
 * LOGIN AUDIT PATTERN (two-phase):
 * - Success audits are written INSIDE the transaction (committed atomically).
 * - Failure audits are written OUTSIDE the transaction (catch block) so they
 *   survive the rollback. Writing them inside and then throwing would wipe
 *   the audit row on rollback.
 */

import type { DbExecutor } from '../../shared/db/db';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { PasswordHasher } from '../../shared/security/password-hasher';
import type { Logger } from '../../shared/logger/logger';
import type { RateLimiter } from '../../shared/security/rate-limit';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import { AuditWriter } from '../../shared/audit/audit.writer';
import type { SessionStore } from '../../shared/session/session.store';

import type { UserRepo } from '../users/dal/user.repo';
import type { MembershipRepo } from '../memberships/dal/membership.repo';

import type { AuthRepo } from './dal/auth.repo';
import { AuthErrors } from './auth.errors';
import type { AuthResult } from './auth.types';

import { auditLoginSuccess, auditLoginFailed } from './auth.audit';

import { resolveTenantForAuth } from './helpers/resolve-tenant-for-auth';
import { validateInviteForRegister } from './helpers/validate-invite-for-register';
import { ensurePasswordIdentity } from './helpers/ensure-password-identity';
import { provisionUserToTenant } from '../_shared/use-cases/provision-user-to-tenant.usecase';
import { writeRegisterAudits } from './helpers/write-register-audits';
import { createAuthSession } from './helpers/create-auth-session';
import { buildAuthResult } from './helpers/build-auth-result';

import { getUserByEmail } from '../users/user.queries';
import { getMembershipByTenantAndUser } from '../memberships/membership.queries';
import { getPasswordIdentityWithHash } from './auth.queries';
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

// ── Rate-limit constants ────────────────────────────────────

const REGISTER_LIMIT_PER_EMAIL = { limit: 5, windowSeconds: 900 };
const REGISTER_LIMIT_PER_IP = { limit: 20, windowSeconds: 900 };
const LOGIN_LIMIT_PER_EMAIL = { limit: 5, windowSeconds: 900 };
const LOGIN_LIMIT_PER_IP = { limit: 20, windowSeconds: 900 };

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

    // Rate limit (before any DB work)
    await this.deps.rateLimiter.hitOrThrow({
      key: `register:email:${email}`,
      ...REGISTER_LIMIT_PER_EMAIL,
    });
    await this.deps.rateLimiter.hitOrThrow({
      key: `register:ip:${params.ip}`,
      ...REGISTER_LIMIT_PER_IP,
    });

    // Transaction: resolve tenant → validate invite → provision user
    //              → ensure identity → write audits
    const { user, membership, tenant } = await this.deps.db.transaction().execute(async (trx) => {
      const userRepo = this.deps.userRepo.withDb(trx);
      const membershipRepo = this.deps.membershipRepo.withDb(trx);
      const authRepo = this.deps.authRepo.withDb(trx);

      const baseAudit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      });

      // 1) Resolve + assert tenant
      const tenant = await resolveTenantForAuth(trx, params.tenantKey);

      // 2) Validate invite (ACCEPTED + email match)
      const invite = await validateInviteForRegister({
        trx,
        tokenHasher: this.deps.tokenHasher,
        tenantId: tenant.id,
        inviteToken: params.inviteToken,
        email,
      });

      // 3) Find-or-create user + create/activate membership
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

      // 4) Guard duplicate registration + hash + insert password identity
      await ensurePasswordIdentity({
        trx,
        authRepo,
        passwordHasher: this.deps.passwordHasher,
        userId: provisionResult.user.id,
        rawPassword: params.password,
      });

      // 5) Write all applicable audit events
      const fullAudit = baseAudit.withContext({
        tenantId: tenant.id,
        userId: provisionResult.user.id,
        membershipId: provisionResult.membership.id,
      });

      await writeRegisterAudits(fullAudit, provisionResult);

      return { ...provisionResult, tenant };
    });

    // 6) Create session (outside tx — Redis, not Postgres)
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

    // Rate limit (before any DB work)
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
        // Audit writer bound to transaction (success path only)
        const audit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
          requestId: params.requestId,
          ip: params.ip,
          userAgent: params.userAgent,
        });

        // 1) Resolve + assert tenant
        const tenant = await resolveTenantForAuth(trx, params.tenantKey);

        // 2) Find user by email (global)
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

        // 3) Find password identity
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

        // 4) Verify password
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

        // 5) Load membership for this tenant
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

        // 6) Enforce membership status
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

        // 7) Audit success (inside tx — committed atomically with reads)
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
      // Phase 2: write failure audit OUTSIDE the rolled-back transaction.
      // This is intentional — the audit row must survive the rollback.
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

    // 8) Create session (outside tx — Redis)
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
}
