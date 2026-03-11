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
import { AppError } from '../../../../shared/http/errors';

import { resolveTenantForAuth, Tenant } from '../../../tenants';
import { isEmailDomainAllowed } from '../../../tenants';

import { findOrCreateUser } from '../../../users';
import { getMembershipByTenantAndUser } from '../../../memberships';

import type { MembershipRepo } from '../../../memberships';
import type { UserRepo } from '../../../users';
import type { AuthRepo } from '../../dal/auth.repo';

import { AuthErrors } from '../../auth.errors';
import { AUTH_RATE_LIMITS } from '../../auth.constants';

import { decryptAndValidateSsoState } from '../../helpers/sso-state-validate';
import type { SsoProvider } from '../../helpers/sso-state';
import { findSsoIdentityByUserAndProvider } from '../../queries/auth.queries';
import {
  auditMembershipActivated,
  auditSsoLoginFailed,
  auditSsoLoginSuccess,
} from '../../auth.audit';

import { hasVerifiedMfaSecret } from '../../helpers/has-verified-mfa-secret';
import { isMfaRequiredForLogin } from '../../policies/mfa-required.policy';

import { createAuthSession } from '../../helpers/create-auth-session';

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
  user: { id: string; email: string; name: string | null; emailVerified: boolean };
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
  const ipKey = deps.tokenHasher.hash(params.ip);

  await deps.rateLimiter.hitOrThrow({
    key: `sso-callback:ip:${ipKey}`,
    ...AUTH_RATE_LIMITS.ssoCallback.perIp,
  });

  let txResult: TxResult;

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

      const tenant = await resolveTenantForAuth(trx, params.tenantKey);
      failureAuditCtx.tenantId = tenant.id;

      if (!tenant.allowedSso.includes(params.provider)) {
        throw new SsoDeniedError({
          appError: AuthErrors.ssoProviderNotAllowed(),
          audit: {
            ctx: toFailureAuditContext({ tenantId: tenant.id }),
            payload: { provider: params.provider, reason: 'provider_not_allowed' },
          },
        });
      }

      const statePayload = decryptAndValidateSsoState({
        encryptionService: deps.sso.stateEncryptionService,
        encryptedState: params.state,
        provider: params.provider,
        tenantKey: tenant.key,
        now: new Date(),
      });

      // WHY: Use the redirectUri embedded in the encrypted state, not the
      // global redirectBaseUrl config. This ensures the token exchange uses
      // the exact URI registered with the provider at SSO start time,
      // which is tenant-aware (e.g. goodwill-ca.hubins.com vs acme.hubins.com).
      const redirectUri = statePayload.redirectUri;

      const adapter = deps.sso.providerRegistry.getOrThrow(params.provider);

      const tokens = await adapter.exchangeAuthorizationCode({
        code: params.code,
        redirectUri,
      });

      const identity = await adapter.validateAndExtractIdentity({
        idToken: tokens.idToken,
        expectedNonce: statePayload.nonce,
        now: new Date(),
      });

      if (!isEmailDomainAllowed(tenant, identity.email)) {
        throw new SsoDeniedError({
          appError: AuthErrors.noAccess(),
          audit: {
            ctx: toFailureAuditContext({ tenantId: tenant.id }),
            payload: { provider: params.provider, reason: 'email_domain_not_allowed' },
          },
        });
      }

      const emailKey = deps.tokenHasher.hash(identity.email);

      const { user } = await findOrCreateUser({
        trx,
        userRepo: deps.userRepo.withDb(trx),
        email: identity.email,
        name: identity.name ?? null,
        now: new Date(),
      });

      failureAuditCtx.userId = user.id;

      const membership = await getMembershipByTenantAndUser(trx, {
        tenantId: tenant.id,
        userId: user.id,
      });

      if (!membership) {
        throw new SsoDeniedError({
          appError: AuthErrors.noAccess(),
          audit: {
            ctx: toFailureAuditContext({ tenantId: tenant.id, userId: user.id }),
            payload: { provider: params.provider, reason: 'membership_missing', emailKey },
          },
        });
      }

      failureAuditCtx.membershipId = membership.id;

      if (membership.status === 'SUSPENDED') {
        throw new SsoDeniedError({
          appError: AuthErrors.noAccess(),
          audit: {
            ctx: toFailureAuditContext({
              tenantId: tenant.id,
              userId: user.id,
              membershipId: membership.id,
            }),
            payload: { provider: params.provider, reason: 'membership_suspended', emailKey },
          },
        });
      }

      const existingIdentity = await findSsoIdentityByUserAndProvider(trx, {
        userId: user.id,
        provider: params.provider,
      });

      if (existingIdentity) {
        if (existingIdentity.providerSubject !== identity.sub) {
          throw new SsoDeniedError({
            appError: AppError.forbidden('SSO identity mismatch.'),
            audit: {
              ctx: toFailureAuditContext({
                tenantId: tenant.id,
                userId: user.id,
                membershipId: membership.id,
              }),
              payload: { provider: params.provider, reason: 'subject_mismatch', emailKey },
            },
          });
        }
      } else {
        await deps.authRepo.withDb(trx).insertSsoIdentity({
          userId: user.id,
          provider: params.provider,
          providerSubject: identity.sub,
        });
      }

      if (membership.status === 'INVITED') {
        await deps.membershipRepo.withDb(trx).activateMembership({
          membershipId: membership.id,
          acceptedAt: new Date(),
        });

        await auditMembershipActivated(
          audit.withContext({
            tenantId: tenant.id,
            userId: user.id,
            membershipId: membership.id,
          }),
          {
            membershipId: membership.id,
            userId: user.id,
            role: membership.role,
          },
        );
      }

      await auditSsoLoginSuccess(
        audit.withContext({
          tenantId: tenant.id,
          userId: user.id,
          membershipId: membership.id,
        }),
        {
          userId: user.id,
          membershipId: membership.id,
          provider: params.provider,
          role: membership.role,
        },
      );

      return {
        user,
        membership: {
          id: membership.id,
          role: membership.role,
          status: membership.status === 'INVITED' ? 'ACTIVE' : membership.status,
        },
        tenant,
      };
    });
  } catch (err) {
    if (err instanceof SsoDeniedError) {
      if (err.audit.ctx.tenantId) {
        try {
          const audit = new AuditWriter(deps.auditRepo, {
            requestId: params.requestId,
            ip: params.ip,
            userAgent: params.userAgent,
          }).withContext(err.audit.ctx);

          await auditSsoLoginFailed(audit, err.audit.payload);
        } catch (auditErr) {
          deps.logger.error({
            msg: 'auth.sso.failure_audit_failed',
            flow: 'auth.sso.callback',
            requestId: params.requestId,
            provider: params.provider,
            error: auditErr,
          });
        }
      }

      throw err.appError;
    }

    throw err;
  }

  const mfaConfigured = await hasVerifiedMfaSecret(deps.db, txResult.user.id);
  const mfaRequired = isMfaRequiredForLogin({
    role: txResult.membership.role,
    tenantMemberMfaRequired: txResult.tenant.memberMfaRequired,
  });

  const { sessionId } = await createAuthSession({
    sessionStore: deps.sessionStore,
    userId: txResult.user.id,
    tenantId: txResult.tenant.id,
    tenantKey: txResult.tenant.key,
    membershipId: txResult.membership.id,
    role: txResult.membership.role,
    tenant: txResult.tenant,
    hasVerifiedMfaSecret: mfaConfigured,
    emailVerified: txResult.user.emailVerified,
    now: new Date(),
  });

  const nextAction = mfaRequired ? (mfaConfigured ? 'MFA_REQUIRED' : 'MFA_SETUP_REQUIRED') : 'NONE';

  const redirectTo = `/auth/sso/done?nextAction=${encodeURIComponent(nextAction)}`;

  deps.logger.info({
    msg: 'auth.sso.callback.success',
    flow: 'auth.sso.callback',
    requestId: params.requestId,
    provider: params.provider,
    tenantId: txResult.tenant.id,
    userId: txResult.user.id,
    membershipId: txResult.membership.id,
    nextAction,
  });

  return { sessionId, redirectTo };
}
