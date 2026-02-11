/**
 * backend/src/modules/auth/auth.service.ts
 *
 * WHY:
 * - Orchestrates password registration (7b) and login (7c) end-to-end.
 * - Only place in the auth module allowed to start transactions.
 * - Creates users, auth identities, activates memberships, creates sessions.
 *
 * RULES:
 * - No raw DB access outside queries/DAL.
 * - Enforce tenant safety.
 * - Never store/log raw passwords or tokens.
 * - Audit meaningful actions via AuditWriter (progressive context enrichment).
 * - Rate limit at the start of each flow (before any DB work).
 *
 * LOGIN AUDIT PATTERN:
 * - Success audits are written INSIDE the transaction (committed atomically with reads).
 * - Failure audits are written OUTSIDE the transaction (in the catch block) so they
 *   survive the rollback. If we wrote them inside and then threw, the rollback would
 *   wipe the audit row.
 */

import type { DbExecutor } from '../../shared/db/db';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { PasswordHasher } from '../../shared/security/password-hasher';
import type { Logger } from '../../shared/logger/logger';
import type { RateLimiter } from '../../shared/security/rate-limit';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import { AuditWriter } from '../../shared/audit/audit.writer';

import type { SessionStore } from '../../shared/session/session.store';

import {
  assertTenantExists,
  assertTenantIsActive,
  assertTenantKeyPresent,
} from '../tenants/policies/tenant-safety.policy';
import { getTenantByKey } from '../tenants/tenant.queries';
import type { Tenant } from '../tenants/tenant.types';

import { getUserByEmail } from '../users/user.queries';
import type { UserRepo } from '../users/dal/user.repo';

import { getMembershipByTenantAndUser } from '../memberships/membership.queries';
import type { MembershipRepo } from '../memberships/dal/membership.repo';

import { getInviteByTenantAndTokenHash } from '../invites/invite.queries';

import { getPasswordIdentityWithHash } from './auth.queries';
import type { AuthRepo } from './dal/auth.repo';
import { AuthErrors } from './auth.errors';
import type { AuthResult, MfaNextAction } from './auth.types';
import {
  auditRegisterSuccess,
  auditUserCreated,
  auditMembershipActivated,
  auditMembershipCreated,
  auditLoginSuccess,
  auditLoginFailed,
} from './auth.audit';

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

// ── Transaction result types (no any) ───────────────────────

type RegisterTxResult = {
  user: { id: string; email: string; name: string | null };
  membership: { id: string; role: 'ADMIN' | 'MEMBER' };
  tenant: Tenant;
};

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

  // ── Register (Brick 7b) ─────────────────────────────────

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

    // Transaction: create user + identity + membership + audit
    const txResult = await this.deps.db
      .transaction()
      .execute(async (trx): Promise<RegisterTxResult> => {
        // Bind repos to transaction
        const userRepo = this.deps.userRepo.withDb(trx);
        const membershipRepo = this.deps.membershipRepo.withDb(trx);
        const authRepo = this.deps.authRepo.withDb(trx);

        // Audit writer with request context
        const audit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
          requestId: params.requestId,
          ip: params.ip,
          userAgent: params.userAgent,
        });

        // 1) Tenant resolution
        assertTenantKeyPresent(params.tenantKey);
        const tenant = await getTenantByKey(trx, params.tenantKey);
        assertTenantExists(tenant, params.tenantKey);
        assertTenantIsActive(tenant);

        const tenantAudit = audit.withContext({ tenantId: tenant.id });

        // 2) Validate invite token
        const tokenHash = this.deps.tokenHasher.hash(params.inviteToken);
        const invite = await getInviteByTenantAndTokenHash(trx, {
          tenantId: tenant.id,
          tokenHash,
        });

        if (!invite || invite.status !== 'ACCEPTED') {
          throw AuthErrors.inviteNotAccepted();
        }

        // 3) Email must match invite
        if (invite.email.toLowerCase() !== email) {
          throw AuthErrors.emailMismatch();
        }

        // 4) Find or create user (global)
        let user = await getUserByEmail(trx, email);
        let userCreated = false;

        if (!user) {
          const created = await userRepo.insertUser({ email, name: params.name });
          user = {
            id: created.id,
            email: created.email,
            name: params.name,
            createdAt: now,
            updatedAt: now,
          };
          userCreated = true;
        }

        const userAudit = tenantAudit.withContext({ userId: user.id });

        // 5) Create password identity (reject if already exists)
        const existingIdentity = await getPasswordIdentityWithHash(trx, user.id);
        if (existingIdentity) {
          throw AuthErrors.alreadyRegistered();
        }

        const passwordHash = await this.deps.passwordHasher.hash(params.password);
        await authRepo.insertPasswordIdentity({
          userId: user.id,
          passwordHash,
        });

        // 6) Create or activate membership
        let membership = await getMembershipByTenantAndUser(trx, {
          tenantId: tenant.id,
          userId: user.id,
        });

        let membershipActivated = false;
        let membershipCreated = false;

        if (membership) {
          if (membership.status === 'SUSPENDED') {
            throw AuthErrors.accountSuspended();
          }
          if (membership.status === 'INVITED') {
            const activated = await membershipRepo.activateMembership({
              membershipId: membership.id,
              acceptedAt: now,
            });
            if (activated) {
              membership = { ...membership, status: 'ACTIVE', acceptedAt: now };
              membershipActivated = true;
            }
          }
          // ACTIVE → ok (idempotent)
        } else {
          const role: 'ADMIN' | 'MEMBER' = invite.role === 'ADMIN' ? 'ADMIN' : 'MEMBER';

          const created = await membershipRepo.insertMembership({
            tenantId: tenant.id,
            userId: user.id,
            role,
            status: 'ACTIVE',
            invitedAt: now,
          });

          membership = {
            id: created.id,
            tenantId: tenant.id,
            userId: user.id,
            role,
            status: 'ACTIVE',
            invitedAt: now,
            acceptedAt: now,
            suspendedAt: null,
            createdAt: now,
            updatedAt: now,
          };
          membershipCreated = true;
        }

        const fullAudit = userAudit.withContext({ membershipId: membership.id });

        // 7) Audit events
        if (userCreated) {
          await auditUserCreated(fullAudit, { userId: user.id, email: user.email });
        }
        if (membershipActivated) {
          await auditMembershipActivated(fullAudit, {
            membershipId: membership.id,
            userId: user.id,
            role: membership.role,
          });
        }
        if (membershipCreated) {
          await auditMembershipCreated(fullAudit, {
            membershipId: membership.id,
            userId: user.id,
            role: membership.role,
          });
        }
        await auditRegisterSuccess(fullAudit, {
          userId: user.id,
          email: user.email,
          membershipId: membership.id,
          role: membership.role,
        });

        return {
          user: { id: user.id, email: user.email, name: user.name ?? null },
          membership: { id: membership.id, role: membership.role },
          tenant,
        };
      });

    const { user, membership, tenant } = txResult;

    // 8) Create session (outside tx — Redis, not Postgres)
    const nextAction = this.determineMfaNextAction(membership.role, tenant);

    const sessionId = await this.deps.sessionStore.create({
      userId: user.id,
      tenantId: tenant.id,
      tenantKey: tenant.key, // for session middleware tenant safety check
      membershipId: membership.id,
      role: membership.role,
      mfaVerified: nextAction === 'NONE', // fully verified only if no MFA needed
      createdAt: now.toISOString(),
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
      result: {
        status: 'AUTHENTICATED',
        nextAction,
        user: { id: user.id, email: user.email, name: user.name ?? '' },
        membership: { id: membership.id, role: membership.role },
      },
    };
  }

  // ── Login (Brick 7c) ───────────────────────────────────

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
        // Audit writer bound to transaction (for success path ONLY)
        const audit = new AuditWriter(this.deps.auditRepo.withDb(trx), {
          requestId: params.requestId,
          ip: params.ip,
          userAgent: params.userAgent,
        });

        // 1) Tenant resolution
        assertTenantKeyPresent(params.tenantKey);
        const tenant = await getTenantByKey(trx, params.tenantKey);
        assertTenantExists(tenant, params.tenantKey);
        assertTenantIsActive(tenant);

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

        const fullAudit = audit
          .withContext({ tenantId: tenant.id })
          .withContext({ userId: user.id, membershipId: membership.id });

        // 7) Audit success (inside tx — committed atomically with reads)
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
      // Phase 2: write failure audit OUTSIDE the rolled-back transaction
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
    const nextAction = this.determineMfaNextAction(membership.role, tenant);

    const sessionId = await this.deps.sessionStore.create({
      userId: user.id,
      tenantId: tenant.id,
      tenantKey: tenant.key, // for session middleware tenant safety check
      membershipId: membership.id,
      role: membership.role,
      mfaVerified: nextAction === 'NONE',
      createdAt: new Date().toISOString(),
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
      result: {
        status: 'AUTHENTICATED',
        nextAction,
        user: { id: user.id, email: user.email, name: user.name ?? '' },
        membership: { id: membership.id, role: membership.role },
      },
    };
  }

  // ── MFA requirement helper ────────────────────────────

  private determineMfaNextAction(role: 'ADMIN' | 'MEMBER', tenant: Tenant): MfaNextAction {
    if (role === 'ADMIN') {
      return 'MFA_SETUP_REQUIRED';
    }

    if (tenant.memberMfaRequired) {
      return 'MFA_SETUP_REQUIRED';
    }

    return 'NONE';
  }
}
