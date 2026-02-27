/**
 * backend/src/modules/auth/flows/signup/execute-signup-flow.ts
 *
 * WHY:
 * - Brick 11: public self-service signup when tenant.public_signup_enabled = true.
 * - Distinct from invite-based registration (Brick 7): no inviteToken, requires
 *   email verification for new users, enforces tenant signup settings.
 * - PR2: swaps fire-and-forget queue email to durable DB outbox row.
 *
 * WHAT IT DOES:
 * - Rate limits early (perEmail hard, perIp hard).
 * - Resolves and validates tenant (active + signup enabled + email domain check).
 * - Checks existing membership state (ACTIVE → conflict, INVITED → conflict,
 *   SUSPENDED → forbidden, none → proceed).
 * - Uses provisionUserToTenant with emailVerifiedForNewUser=false for new users.
 * - For existing users joining a new tenant: user.emailVerified is already true
 *   (they registered elsewhere), no verification needed.
 * - Creates password identity ONLY when the user does not already have one.
 * - Enqueues verification email only for newly created, unverified users.
 * - Writes audit inside tx, creates session outside tx.
 *
 * RULES:
 * - Opens its own transaction (flow layer).
 * - No HTTP concerns.
 * - No raw SQL.
 * - Outbox row is written in the SAME DB transaction as token insert.
 * - Outbox payload must never store raw email/token (tokenEnc + toEmailEnc only).
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { PasswordHasher } from '../../../../shared/security/password-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { SessionStore } from '../../../../shared/session/session.store';

import type { UserRepo } from '../../../users/dal/user.repo';
import type { MembershipRepo } from '../../../memberships/dal/membership.repo';
import type { AuthRepo } from '../../dal/auth.repo';
import type { EmailVerificationRepo } from '../../dal/email-verification.repo';

import type { AuthResult } from '../../auth.types';

import { resolveTenantForAuth, assertEmailDomainAllowed } from '../../../tenants';
import { getUserByEmail } from '../../../users';
import { getMembershipByTenantAndUser } from '../../../memberships';
import { provisionUserToTenant } from '../../../_shared/use-cases/provision-user-to-tenant.usecase';
import { ensurePasswordIdentity } from '../../helpers/ensure-password-identity';
import { createAuthSession } from '../../helpers/create-auth-session';
import { buildAuthResult } from '../../helpers/build-auth-result';
import { hasAuthIdentity } from '../../queries/auth.queries';

import { AuthErrors } from '../../auth.errors';

import {
  auditSignupSuccess,
  auditUserCreated,
  auditMembershipCreated,
  auditMembershipActivated,
} from '../../auth.audit';

import { generateSecureToken } from '../../../../shared/security/token';
import { AUTH_RATE_LIMITS, EMAIL_VERIFICATION_TTL_SECONDS } from '../../auth.constants';
import { emailDomain } from '../../helpers/email-domain';

// Outbox (PR2)
import type { OutboxRepo } from '../../../../shared/outbox/outbox.repo';
import type { OutboxEncryption } from '../../../../shared/outbox/outbox-encryption';

export type SignupParams = {
  tenantKey: string | null;
  email: string;
  password: string;
  name: string;
  ip: string;
  userAgent: string | null;
  requestId: string;
};

type SignupTxResult = {
  user: { id: string; email: string; name: string | null; emailVerified: boolean };
  membership: { id: string; role: 'ADMIN' | 'MEMBER'; status: 'ACTIVE' | 'INVITED' | 'SUSPENDED' };
  tenant: import('../../../tenants').Tenant;
  verificationEnqueued: boolean;
};

export async function executeSignupFlow(
  deps: {
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
    emailVerificationRepo: EmailVerificationRepo;

    // Outbox (PR2)
    outboxRepo: OutboxRepo;
    outboxEncryption: OutboxEncryption;
  },
  params: SignupParams,
): Promise<{ result: AuthResult; sessionId: string }> {
  const email = params.email.toLowerCase();
  const emailKey = deps.tokenHasher.hash(email);
  const now = new Date();

  deps.logger.info({
    msg: 'auth.signup.start',
    flow: 'auth.signup',
    requestId: params.requestId,
    tenantKey: params.tenantKey,
    emailDomain: emailDomain(email),
    emailKey,
  });

  // ── Rate limits (before any DB work) ──────────────────────────────────────
  await deps.rateLimiter.hitOrThrow({
    key: `signup:email:${emailKey}`,
    ...AUTH_RATE_LIMITS.signup.perEmail,
  });
  await deps.rateLimiter.hitOrThrow({
    key: `signup:ip:${params.ip}`,
    ...AUTH_RATE_LIMITS.signup.perIp,
  });

  // ── Transaction ───────────────────────────────────────────────────────────
  const txResult = await deps.db.transaction().execute(async (trx): Promise<SignupTxResult> => {
    const userRepo = deps.userRepo.withDb(trx);
    const membershipRepo = deps.membershipRepo.withDb(trx);
    const authRepo = deps.authRepo.withDb(trx);
    const emailVerificationRepo = deps.emailVerificationRepo.withDb(trx);

    const baseAudit = new AuditWriter(deps.auditRepo.withDb(trx), {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    });

    // ── A. Resolve tenant ────────────────────────────────────────────────────
    const tenant = await resolveTenantForAuth(trx, params.tenantKey);

    // ── B. Enforce tenant signup settings ────────────────────────────────────
    if (!tenant.publicSignupEnabled) {
      throw AuthErrors.signupDisabled();
    }
    assertEmailDomainAllowed(tenant, email);

    // ── C. Check existing user + membership state ────────────────────────────
    const existingUser = await getUserByEmail(trx, email);

    if (existingUser) {
      const existingMembership = await getMembershipByTenantAndUser(trx, {
        tenantId: tenant.id,
        userId: existingUser.id,
      });

      if (existingMembership) {
        if (existingMembership.status === 'SUSPENDED') throw AuthErrors.accountSuspended();
        if (existingMembership.status === 'INVITED') throw AuthErrors.emailInvitePending();
        if (existingMembership.status === 'ACTIVE') throw AuthErrors.emailAlreadyMember();
      }
    }

    // ── D. Provision user + membership ───────────────────────────────────────
    const provisionResult = await provisionUserToTenant({
      trx,
      userRepo,
      membershipRepo,
      email,
      name: params.name,
      tenantId: tenant.id,
      role: 'MEMBER',
      now,
      emailVerifiedForNewUser: false,
    });

    const { user, membership } = provisionResult;

    // ── E. Create password identity (only when needed) ────────────────────────
    const alreadyHasPasswordIdentity = await hasAuthIdentity(trx, {
      userId: user.id,
      provider: 'password',
    });

    if (!alreadyHasPasswordIdentity) {
      await ensurePasswordIdentity({
        trx,
        authRepo,
        passwordHasher: deps.passwordHasher,
        userId: user.id,
        rawPassword: params.password,
      });
    }

    // ── F. Email verification token + Outbox enqueue (only for unverified) ───
    let verificationEnqueued = false;

    if (!user.emailVerified) {
      await emailVerificationRepo.invalidateActiveVerificationTokensForUser({ userId: user.id });

      const rawToken = generateSecureToken();
      const tokenHash = deps.tokenHasher.hash(rawToken);
      const expiresAt = new Date(now.getTime() + EMAIL_VERIFICATION_TTL_SECONDS * 1000);

      await emailVerificationRepo.insertVerificationToken({
        userId: user.id,
        tokenHash,
        expiresAt,
      });

      const payload = deps.outboxEncryption.encryptPayload({
        token: rawToken,
        toEmail: user.email,
        tenantKey: tenant.key,
        userId: user.id,
      });

      await deps.outboxRepo.enqueueWithinTx(trx, {
        type: 'email.verify',
        payload,
        idempotencyKey: `email-verify:${user.id}:${tokenHash}`,
      });

      verificationEnqueued = true;
    }

    // ── G. Audit (inside tx) ──────────────────────────────────────────────────
    const fullAudit = baseAudit
      .withContext({ tenantId: tenant.id })
      .withContext({ userId: user.id, membershipId: membership.id });

    if (provisionResult.userCreated) {
      await auditUserCreated(fullAudit, { userId: user.id });
    }
    if (provisionResult.membershipActivated) {
      await auditMembershipActivated(fullAudit, {
        membershipId: membership.id,
        userId: user.id,
        role: membership.role,
      });
    }
    if (provisionResult.membershipCreated) {
      await auditMembershipCreated(fullAudit, {
        membershipId: membership.id,
        userId: user.id,
        role: membership.role,
      });
    }

    await auditSignupSuccess(fullAudit, {
      userId: user.id,
      membershipId: membership.id,
      role: membership.role,
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name ?? null,
        emailVerified: user.emailVerified,
      },
      membership: { id: membership.id, role: membership.role, status: membership.status },
      tenant,
      verificationEnqueued,
    };
  });

  // ── Session + nextAction ───────────────────────────────────────────────
  const { sessionId } = await createAuthSession({
    sessionStore: deps.sessionStore,
    userId: txResult.user.id,
    tenantId: txResult.tenant.id,
    tenantKey: txResult.tenant.key,
    membershipId: txResult.membership.id,
    role: txResult.membership.role,
    tenant: txResult.tenant,
    hasVerifiedMfaSecret: false,
    emailVerified: txResult.user.emailVerified,
    now,
  });

  deps.logger.info({
    msg: 'auth.signup.success',
    flow: 'auth.signup',
    requestId: params.requestId,
    tenantId: txResult.tenant.id,
    userId: txResult.user.id,
    membershipId: txResult.membership.id,
    emailVerified: txResult.user.emailVerified,
    verificationEnqueued: txResult.verificationEnqueued,
  });

  return {
    sessionId,
    result: buildAuthResult({
      nextAction: txResult.user.emailVerified ? 'NONE' : 'EMAIL_VERIFICATION_REQUIRED',
      user: txResult.user,
      membership: txResult.membership,
    }),
  };
}
