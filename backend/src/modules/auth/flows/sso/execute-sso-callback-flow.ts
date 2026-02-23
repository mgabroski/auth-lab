/**
 * backend/src/modules/auth/flows/sso/execute-sso-callback-flow.ts
 *
 * WHY:
 * - Brick 10: SSO login callback orchestration (Google in PR2).
 * - Follows locked order A–M (tenant → gates → state → exchange → validate → tx provisioning → MFA → session → redirect).
 *
 * RULES:
 * - No HTTP concerns here.
 * - No raw SQL: use queries/repos.
 * - Transaction opened here.
 * - Success audit inside tx; failure audit outside tx.
 */

import type { DbExecutor } from '../../../../shared/db/db';
import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { Logger } from '../../../../shared/logger/logger';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { AuditRepo } from '../../../../shared/audit/audit.repo';
import { AuditWriter } from '../../../../shared/audit/audit.writer';
import type { SessionStore } from '../../../../shared/session/session.store';
import type { EncryptionService } from '../../../../shared/security/encryption';

import { resolveTenantForAuth, Tenant } from '../../../tenants';

import { getUserByEmail } from '../../../users';
import { getMembershipByTenantAndUser } from '../../../memberships';

import type { MembershipRepo } from '../../../memberships/dal/membership.repo';
import type { UserRepo } from '../../../users/dal/user.repo';
import type { AuthRepo } from '../../dal/auth.repo';

import { AuthErrors } from '../../auth.errors';
import { AUTH_RATE_LIMITS } from '../../auth.constants';

import { decryptAndValidateSsoState } from '../../helpers/sso-state-validate';
import type { SsoProvider } from '../../helpers/sso-state';
import { emailDomain } from '../../helpers/email-domain';

import {
  exchangeGoogleAuthorizationCode,
  validateAndExtractGoogleIdentity,
} from '../../sso/google/google-sso.provider';

import { findSsoIdentityByUserAndProvider } from '../../queries/auth.queries';
import { auditSsoLoginFailed, auditSsoLoginSuccess } from '../../auth.audit';

import { hasVerifiedMfaSecret } from '../../helpers/has-verified-mfa-secret';
import { isMfaRequiredForLogin } from '../../policies/mfa-required.policy';
import { decideLoginNextAction } from '../../policies/login-next-action.policy';

import { createAuthSession } from '../../helpers/create-auth-session';

function isEmailDomainAllowed(allowedDomains: string[], email: string): boolean {
  if (!allowedDomains.length) return true;
  const d = emailDomain(email);
  if (!d) return false;
  return allowedDomains.includes(d);
}

export type SsoCallbackParams = {
  tenantKey: string | null;
  provider: SsoProvider; // google for PR2
  code: string;
  state: string;

  ip: string;
  userAgent: string | null;
  requestId: string;
};

type TxResult = {
  user: { id: string; email: string; name: string | null };
  membership: { id: string; role: 'ADMIN' | 'MEMBER'; status: 'ACTIVE' | 'INVITED' | 'SUSPENDED' };
  tenant: Tenant;
};

type FailureAuditContext = {
  tenantId: string;
  userId: string | null;
  membershipId: string | null;
};

type FailureAuditPayload = {
  provider: 'google' | 'microsoft';
  reason: string;
  emailKey?: string;
};

class SsoDeniedError extends Error {
  readonly appError: Error;
  readonly audit: { ctx: FailureAuditContext; payload: FailureAuditPayload };

  constructor(input: {
    appError: Error;
    audit: { ctx: FailureAuditContext; payload: FailureAuditPayload };
  }) {
    super('sso_denied');
    this.name = 'SsoDeniedError';
    this.appError = input.appError;
    this.audit = input.audit;
  }
}

function toFailureAuditContext(input: {
  tenantId: string;
  userId?: string;
  membershipId?: string;
}): FailureAuditContext {
  return {
    tenantId: input.tenantId,
    userId: input.userId ?? null,
    membershipId: input.membershipId ?? null,
  };
}

export async function executeSsoCallbackFlow(
  deps: {
    db: DbExecutor;
    tokenHasher: TokenHasher;
    logger: Logger;
    rateLimiter: RateLimiter;
    auditRepo: AuditRepo;
    sessionStore: SessionStore;

    userRepo: UserRepo;
    membershipRepo: MembershipRepo;
    authRepo: AuthRepo;

    sso: {
      stateEncryptionService: EncryptionService;
      redirectBaseUrl: string;
      googleClientId: string;
      googleClientSecret: string;
    };
  },
  params: SsoCallbackParams,
): Promise<{ sessionId: string; redirectTo: string }> {
  // Rate limit EARLY (before any DB work)
  await deps.rateLimiter.hitOrThrow({
    key: `sso-callback:ip:${params.ip}`,
    ...AUTH_RATE_LIMITS.ssoCallback.perIp,
  });

  let txResult: TxResult;

  try {
    txResult = await deps.db.transaction().execute(async (trx): Promise<TxResult> => {
      const audit = new AuditWriter(deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      });

      // A) Resolve tenant
      const tenant = await resolveTenantForAuth(trx, params.tenantKey);

      // B) Provider allow-list
      if (!tenant.allowedSso.includes(params.provider)) {
        throw new SsoDeniedError({
          appError: AuthErrors.ssoProviderNotAllowed(),
          audit: {
            ctx: toFailureAuditContext({ tenantId: tenant.id }),
            payload: { provider: params.provider, reason: 'provider_not_allowed' },
          },
        });
      }

      // C) Validate encrypted state binding
      const statePayload = decryptAndValidateSsoState({
        encryptionService: deps.sso.stateEncryptionService,
        encryptedState: params.state,
        provider: params.provider,
        tenantKey: tenant.key,
        now: new Date(),
      });

      // D) Exchange code -> tokens (Google only in PR2)
      if (params.provider !== 'google') {
        throw new SsoDeniedError({
          appError: AuthErrors.ssoStateInvalid({ reason: 'provider_not_implemented' }),
          audit: {
            ctx: toFailureAuditContext({ tenantId: tenant.id }),
            payload: { provider: params.provider, reason: 'provider_not_implemented' },
          },
        });
      }

      const redirectUri = `${deps.sso.redirectBaseUrl.replace(/\/+$/g, '')}/auth/sso/google/callback`;

      const tokens = await exchangeGoogleAuthorizationCode({
        code: params.code,
        redirectUri,
        clientId: deps.sso.googleClientId,
        clientSecret: deps.sso.googleClientSecret,
      });

      // E+F) Validate ID token claims + extract identity
      const identity = validateAndExtractGoogleIdentity({
        idToken: tokens.idToken,
        expectedIssuer: 'https://accounts.google.com',
        expectedAudience: deps.sso.googleClientId,
        expectedNonce: statePayload.nonce,
        now: new Date(),
      });

      // Email domain allow-list (after email known)
      if (!isEmailDomainAllowed(tenant.allowedEmailDomains, identity.email)) {
        throw new SsoDeniedError({
          appError: AuthErrors.noAccess(),
          audit: {
            ctx: toFailureAuditContext({ tenantId: tenant.id }),
            payload: { provider: 'google', reason: 'email_domain_not_allowed' },
          },
        });
      }

      const emailKey = deps.tokenHasher.hash(identity.email);

      // G) User (find or create)
      let user = await getUserByEmail(trx, identity.email);

      if (!user) {
        await deps.userRepo.withDb(trx).insertUser({
          email: identity.email,
          name: identity.name ?? null,
        });

        user = await getUserByEmail(trx, identity.email);
        if (!user) {
          throw new Error('auth.sso.callback: user insert succeeded but user not found');
        }
      }

      // H) Membership enforcement (NO CREATE)
      const membership = await getMembershipByTenantAndUser(trx, {
        tenantId: tenant.id,
        userId: user.id,
      });

      if (!membership) {
        throw new SsoDeniedError({
          appError: AuthErrors.noAccess(),
          audit: {
            ctx: toFailureAuditContext({ tenantId: tenant.id, userId: user.id }),
            payload: { provider: 'google', reason: 'no_membership', emailKey },
          },
        });
      }

      if (membership.status === 'SUSPENDED') {
        throw new SsoDeniedError({
          appError: AuthErrors.accountSuspended(),
          audit: {
            ctx: toFailureAuditContext({
              tenantId: tenant.id,
              userId: user.id,
              membershipId: membership.id,
            }),
            payload: { provider: 'google', reason: 'suspended', emailKey },
          },
        });
      }

      if (membership.status === 'INVITED') {
        await deps.membershipRepo.withDb(trx).activateMembership({
          membershipId: membership.id,
          acceptedAt: new Date(),
        });
      }

      // I) Identity upsert + subject drift protection
      const existing = await findSsoIdentityByUserAndProvider(trx, {
        userId: user.id,
        provider: 'google',
      });

      if (existing && existing.providerSubject !== identity.sub) {
        throw new SsoDeniedError({
          appError: AuthErrors.ssoSubjectDrift(),
          audit: {
            ctx: toFailureAuditContext({
              tenantId: tenant.id,
              userId: user.id,
              membershipId: membership.id,
            }),
            payload: { provider: 'google', reason: 'subject_drift', emailKey },
          },
        });
      }

      if (!existing) {
        await deps.authRepo.withDb(trx).insertSsoIdentity({
          userId: user.id,
          provider: 'google',
          providerSubject: identity.sub,
        });
      }

      // Success audit INSIDE tx
      const fullAudit = audit
        .withContext({ tenantId: tenant.id })
        .withContext({ userId: user.id, membershipId: membership.id });

      await auditSsoLoginSuccess(fullAudit, {
        userId: user.id,
        membershipId: membership.id,
        role: membership.role,
        provider: 'google',
      });

      return {
        user: { id: user.id, email: user.email, name: user.name ?? null },
        membership: { id: membership.id, role: membership.role, status: membership.status },
        tenant,
      };
    });
  } catch (err) {
    // Failure audit OUTSIDE tx (survive rollback)
    if (err instanceof SsoDeniedError) {
      const writer = new AuditWriter(deps.auditRepo, {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext(err.audit.ctx);

      await auditSsoLoginFailed(writer, err.audit.payload);
      throw err.appError;
    }

    throw err;
  }

  // J) MFA rule enforcement (outside tx)
  const mfaIsRequired = isMfaRequiredForLogin({
    role: txResult.membership.role,
    tenantMemberMfaRequired: txResult.tenant.memberMfaRequired,
  });

  const hasVerifiedMfaSecretValue = mfaIsRequired
    ? await hasVerifiedMfaSecret(deps.db, txResult.user.id)
    : false;

  const nextAction = decideLoginNextAction({
    role: txResult.membership.role,
    memberMfaRequired: txResult.tenant.memberMfaRequired,
    hasVerifiedMfaSecret: hasVerifiedMfaSecretValue,
  });

  // K) Session creation (outside tx)
  const { sessionId } = await createAuthSession({
    sessionStore: deps.sessionStore,
    userId: txResult.user.id,
    tenantId: txResult.tenant.id,
    tenantKey: txResult.tenant.key,
    membershipId: txResult.membership.id,
    role: txResult.membership.role,
    tenant: txResult.tenant,
    hasVerifiedMfaSecret: hasVerifiedMfaSecretValue,
    now: new Date(),
  });

  // L) Success redirect
  const redirectTo = `${deps.sso.redirectBaseUrl.replace(/\/+$/g, '')}/auth/sso/done?nextAction=${encodeURIComponent(
    nextAction,
  )}`;

  deps.logger.info({
    msg: 'auth.sso.login.success',
    flow: 'auth.sso.login',
    requestId: params.requestId,
    provider: params.provider,
    tenantKey: params.tenantKey,
    tenantId: txResult.tenant.id,
    userId: txResult.user.id,
    membershipId: txResult.membership.id,
  });

  return { sessionId, redirectTo };
}
