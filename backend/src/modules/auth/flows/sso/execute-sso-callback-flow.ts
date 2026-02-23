/**
 * backend/src/modules/auth/flows/sso/execute-sso-callback-flow.ts
 *
 * WHY:
 * - Brick 10: SSO login callback orchestration (Google in PR2; Microsoft in PR3).
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
import type { SsoProviderRegistry } from '../../sso/sso-provider-registry';

import { resolveTenantForAuth, Tenant } from '../../../tenants';

import { getUserByEmail } from '../../../users';
import { getMembershipByTenantAndUser } from '../../../memberships';

import type { MembershipRepo } from '../../../memberships/dal/membership.repo';
import type { UserRepo } from '../../../users/dal/user.repo';
import type { AuthRepo } from '../../dal/auth.repo';

import { AuthErrors } from '../../auth.errors';
import { AUTH_RATE_LIMITS } from '../../auth.constants';

import { AppError } from '../../../../shared/http/errors';

import { decryptAndValidateSsoState } from '../../helpers/sso-state-validate';
import type { SsoProvider } from '../../helpers/sso-state';
import { emailDomain } from '../../helpers/email-domain';

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
  provider: SsoProvider;
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
      providerRegistry: SsoProviderRegistry;
    };
  },
  params: SsoCallbackParams,
): Promise<{ sessionId: string; redirectTo: string }> {
  await deps.rateLimiter.hitOrThrow({
    key: `sso-callback:ip:${params.ip}`,
    ...AUTH_RATE_LIMITS.ssoCallback.perIp,
  });

  let txResult: TxResult;

  // Best-effort context for failure audits (written OUTSIDE the tx).
  // This is progressively enriched inside the tx as we learn tenant/user/membership.
  const failureAuditCtx: {
    tenantId: string | null;
    userId: string | null;
    membershipId: string | null;
  } = {
    tenantId: null,
    userId: null,
    membershipId: null,
  };

  try {
    txResult = await deps.db.transaction().execute(async (trx): Promise<TxResult> => {
      const audit = new AuditWriter(deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      });

      // A) Resolve tenant
      const tenant = await resolveTenantForAuth(trx, params.tenantKey);
      failureAuditCtx.tenantId = tenant.id;

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

      // D) Exchange code -> tokens
      const redirectUri = `${deps.sso.redirectBaseUrl.replace(/\/+$/g, '')}/auth/sso/${params.provider}/callback`;

      const adapter = deps.sso.providerRegistry.getOrThrow(params.provider);

      const tokens = await adapter.exchangeAuthorizationCode({
        code: params.code,
        redirectUri,
      });

      // E+F) Validate ID token claims + extract identity
      const identity = adapter.validateAndExtractIdentity({
        idToken: tokens.idToken,
        expectedNonce: statePayload.nonce,
        now: new Date(),
      });

      // Domain allow-list (after email known)
      if (!isEmailDomainAllowed(tenant.allowedEmailDomains, identity.email)) {
        throw new SsoDeniedError({
          appError: AuthErrors.noAccess(),
          audit: {
            ctx: toFailureAuditContext({ tenantId: tenant.id }),
            payload: { provider: params.provider, reason: 'email_domain_not_allowed' },
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
        if (!user) throw new Error('auth.sso.callback: user insert succeeded but user not found');
      }

      failureAuditCtx.userId = user.id;

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
            payload: { provider: params.provider, reason: 'no_membership', emailKey },
          },
        });
      }

      failureAuditCtx.membershipId = membership.id;

      if (membership.status === 'SUSPENDED') {
        throw new SsoDeniedError({
          appError: AuthErrors.accountSuspended(),
          audit: {
            ctx: toFailureAuditContext({
              tenantId: tenant.id,
              userId: user.id,
              membershipId: membership.id,
            }),
            payload: { provider: params.provider, reason: 'suspended', emailKey },
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
        provider: params.provider,
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
            payload: { provider: params.provider, reason: 'subject_drift', emailKey },
          },
        });
      }

      if (!existing) {
        await deps.authRepo.withDb(trx).insertSsoIdentity({
          userId: user.id,
          provider: params.provider,
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
        provider: params.provider,
      });

      return {
        user: { id: user.id, email: user.email, name: user.name ?? null },
        membership: { id: membership.id, role: membership.role, status: membership.status },
        tenant,
      };
    });
  } catch (err) {
    if (err instanceof SsoDeniedError) {
      const writer = new AuditWriter(deps.auditRepo, {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext(err.audit.ctx);

      await auditSsoLoginFailed(writer, err.audit.payload);
      throw err.appError;
    }

    // Token/state validation failures (and other AppErrors) must also be audited.
    // These errors can occur before membership/user is known, so we audit with best-effort context.
    if (err instanceof AppError) {
      const writer = new AuditWriter(deps.auditRepo, {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      }).withContext(failureAuditCtx);

      const reasonFromMeta = typeof err.meta?.reason === 'string' ? err.meta.reason : undefined;

      await auditSsoLoginFailed(writer, {
        provider: params.provider,
        reason: reasonFromMeta ?? `app_error:${err.code}`,
      });

      throw err;
    }

    throw err;
  }

  // J) MFA enforcement (outside tx) — unchanged
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

  // K) Session creation (outside tx) — unchanged
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

  // L) Success redirect — unchanged
  const redirectTo = `${deps.sso.redirectBaseUrl.replace(/\/+$/g, '')}/auth/sso/done?nextAction=${encodeURIComponent(nextAction)}`;

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
