/**
 * backend/src/modules/auth/flows/signup/execute-signup-flow.ts
 *
 * WHY:
 * - Brick 11: public self-service signup when tenant.public_signup_enabled = true.
 * - Distinct from invite-based registration (Brick 7): no inviteToken, requires
 *   email verification for new users, enforces tenant signup settings.
 *
 * WHAT IT DOES:
 * - Rate limits early (perEmail hard, perIp hard).
 * - Resolves and validates tenant (active + signup enabled + email domain check).
 * - Checks existing membership state (ACTIVE → conflict, INVITED → conflict,
 *   SUSPENDED → forbidden, none → proceed).
 * - Uses provisionUserToTenant with emailVerifiedForNewUser=false for new users.
 * - For existing users joining a new tenant: user.emailVerified is already true
 *   (they registered elsewhere), no verification needed.
 * - Creates password identity (ensurePasswordIdentity replay-guards this).
 * - Enqueues verification email only for newly created, unverified users.
 * - Writes audit inside tx, creates session outside tx.
 *
 * RULES:
 * - Opens its own transaction (flow layer).
 * - No HTTP concerns.
 * - No raw SQL.
 * - Failure audits outside tx (survive rollback) — but signup has no dedicated
 *   failure audit (the membership conflict / domain check errors are enough);
 *   this may be added in Brick 13 Audit Hardening.
 *
 * MEMBERSHIP CHECK APPROACH (Decision 5):
 * - Membership is queried by user_id join after user lookup, never by email.
 * - This matches the locked arch rule from the brief.
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { PasswordHasher } from '../../../../shared/security/password-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { SessionStore } from '../../../../shared/session/session.store';
import type { Queue } from '../../../../shared/messaging/queue';

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
  /** Raw token — only present when a verification email needs to be sent. */
  verificationToken: string | null;
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
    queue: Queue;
    userRepo: UserRepo;
    membershipRepo: MembershipRepo;
    authRepo: AuthRepo;
    emailVerificationRepo: EmailVerificationRepo;
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

    // Email domain check (if tenant has a restriction configured).
    assertEmailDomainAllowed(tenant, email);

    // ── C. Check existing user + membership state ────────────────────────────
    // Per Decision 5: check by user_id join, never by email alone.
    const existingUser = await getUserByEmail(trx, email);

    if (existingUser) {
      const existingMembership = await getMembershipByTenantAndUser(trx, {
        tenantId: tenant.id,
        userId: existingUser.id,
      });

      if (existingMembership) {
        if (existingMembership.status === 'SUSPENDED') {
          throw AuthErrors.accountSuspended();
        }
        if (existingMembership.status === 'INVITED') {
          throw AuthErrors.emailInvitePending();
        }
        if (existingMembership.status === 'ACTIVE') {
          throw AuthErrors.emailAlreadyMember();
        }
      }
      // User exists with no membership for this tenant → fall through to
      // provisionUserToTenant which will create the membership as ACTIVE.
    }

    // ── D. Provision user + membership ───────────────────────────────────────
    // emailVerifiedForNewUser=false: new users created via public signup must
    // verify their email. Existing users (userCreated=false) already have
    // emailVerified=true from their original registration — unchanged.
    const provisionResult = await provisionUserToTenant({
      trx,
      userRepo,
      membershipRepo,
      email,
      name: params.name,
      tenantId: tenant.id,
      role: 'MEMBER', // Public signup always creates members, not admins.
      now,
      emailVerifiedForNewUser: false,
    });

    const { user, membership } = provisionResult;

    // ── E. Create password identity ───────────────────────────────────────────
    // ensurePasswordIdentity guards against replay (throws if identity exists).
    await ensurePasswordIdentity({
      trx,
      authRepo,
      passwordHasher: deps.passwordHasher,
      userId: user.id,
      rawPassword: params.password,
    });

    // ── F. Email verification token (only for new unverified users) ───────────
    let verificationToken: string | null = null;

    if (!user.emailVerified) {
      // Invalidate any prior active tokens (one-active-at-a-time rule).
      await emailVerificationRepo.invalidateActiveVerificationTokensForUser({ userId: user.id });

      const rawToken = generateSecureToken();
      const tokenHash = deps.tokenHasher.hash(rawToken);
      const expiresAt = new Date(now.getTime() + EMAIL_VERIFICATION_TTL_SECONDS * 1000);

      await emailVerificationRepo.insertVerificationToken({
        userId: user.id,
        tokenHash,
        expiresAt,
      });

      verificationToken = rawToken;
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
      verificationToken,
    };
  });

  // ── H. Enqueue verification email (outside tx — fire-and-forget) ──────────
  // Only for new users who need to verify. Existing users joining a new tenant
  // are already verified.
  if (txResult.verificationToken) {
    await deps.queue.enqueue({
      type: 'auth.signup-verification-email',
      userId: txResult.user.id,
      email: txResult.user.email,
      verificationToken: txResult.verificationToken,
      tenantKey: txResult.tenant.key,
    });
  }

  // ── I. Session + nextAction ───────────────────────────────────────────────
  // Decision 3: emailVerified=false → nextAction = EMAIL_VERIFICATION_REQUIRED.
  // mfaVerified=false in session. Existing verified users get normal MFA logic.
  const { sessionId } = await createAuthSession({
    sessionStore: deps.sessionStore,
    userId: txResult.user.id,
    tenantId: txResult.tenant.id,
    tenantKey: txResult.tenant.key,
    membershipId: txResult.membership.id,
    role: txResult.membership.role,
    tenant: txResult.tenant,
    // New users via signup never have MFA yet.
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
  });

  return {
    sessionId,
    result: buildAuthResult({
      // buildAuthResult uses decideRegisterNextAction-compatible nextAction;
      // here we compute it via createAuthSession's policy call internally.
      // We need the nextAction to match what createAuthSession computed.
      nextAction: txResult.user.emailVerified ? 'NONE' : 'EMAIL_VERIFICATION_REQUIRED',
      user: txResult.user,
      membership: txResult.membership,
    }),
  };
}
