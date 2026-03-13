/**
 * backend/src/modules/auth/flows/sso/execute-sso-callback-flow.ts
 *
 * WHY:
 * - Brick 10: SSO login callback orchestration (Google in PR2; Microsoft in PR3).
 * - Phase 1B wires the approved tenant-entry policy into runtime callback
 *   behavior so SSO cannot bypass public-signup / invite rules or create orphan
 *   user rows on blocked entry paths.
 *
 * RULES:
 * - No HTTP concerns here.
 * - No raw SQL: use queries/repos/policies.
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

import type { MembershipRepo } from '../../../memberships';
import type { UserRepo } from '../../../users';
import type { AuthRepo } from '../../dal/auth.repo';
import { InviteRepo } from '../../../invites/dal/invite.repo';

import { AuthErrors } from '../../auth.errors';
import { AUTH_RATE_LIMITS } from '../../auth.constants';

import { decryptAndValidateSsoState } from '../../helpers/sso-state-validate';
import type { SsoProvider } from '../../helpers/sso-state';
import { findSsoIdentityByUserAndProvider } from '../../queries/auth.queries';
import {
  auditMembershipActivated,
  auditMembershipCreated,
  auditSsoLoginFailed,
  auditSsoLoginSuccess,
  auditUserCreated,
} from '../../auth.audit';
import { auditInviteAccepted } from '../../../invites/invite.audit';

import { hasVerifiedMfaSecret } from '../../helpers/has-verified-mfa-secret';
import { isMfaRequiredForLogin } from '../../policies/mfa-required.policy';

import { createAuthSession } from '../../helpers/create-auth-session';
import { resolveTenantEntryAuthDecision } from '../../helpers/resolve-tenant-entry-auth-decision';
import { provisionUserToTenant } from '../../../_shared/use-cases/provision-user-to-tenant.usecase';

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

  try {
    txResult = await deps.db.transaction().execute(async (trx): Promise<TxResult> => {
      const now = new Date();
      const audit = new AuditWriter(deps.auditRepo.withDb(trx), {
        requestId: params.requestId,
        ip: params.ip,
        userAgent: params.userAgent,
      });

      const tenant = await resolveTenantForAuth(trx, params.tenantKey);

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
        now,
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
        now,
      });

      const normalizedEmail = identity.email.toLowerCase();
      const emailKey = deps.tokenHasher.hash(normalizedEmail);

      if (!isEmailDomainAllowed(tenant, normalizedEmail)) {
        throw new SsoDeniedError({
          appError: AuthErrors.noAccess(),
          audit: {
            ctx: toFailureAuditContext({ tenantId: tenant.id }),
            payload: { provider: params.provider, reason: 'email_domain_not_allowed', emailKey },
          },
        });
      }

      const resolvedEntry = await resolveTenantEntryAuthDecision({
        db: trx,
        tenant,
        email: normalizedEmail,
        now,
      });

      const userRepo = deps.userRepo.withDb(trx);
      const membershipRepo = deps.membershipRepo.withDb(trx);
      const authRepo = deps.authRepo.withDb(trx);
      const inviteRepo = new InviteRepo(trx);

      let user = resolvedEntry.user;
      let membership = resolvedEntry.membership;
      let inviteAcceptedInThisFlow = false;

      switch (resolvedEntry.decision.code) {
        case 'PUBLIC_SIGNUP_BLOCKED':
        case 'INVITE_REQUIRED':
          throw new SsoDeniedError({
            appError: AuthErrors.signupDisabled(),
            audit: {
              ctx: toFailureAuditContext({
                tenantId: tenant.id,
                userId: resolvedEntry.user?.id,
                membershipId: resolvedEntry.membership?.id,
              }),
              payload: { provider: params.provider, reason: 'signup_disabled', emailKey },
            },
          });

        case 'INVITED_EXPIRED':
          throw new SsoDeniedError({
            appError: AuthErrors.invitationExpired(),
            audit: {
              ctx: toFailureAuditContext({
                tenantId: tenant.id,
                userId: resolvedEntry.user?.id,
                membershipId: resolvedEntry.membership?.id,
              }),
              payload: { provider: params.provider, reason: 'invite_expired', emailKey },
            },
          });

        case 'SUSPENDED_MEMBERSHIP':
          throw new SsoDeniedError({
            appError: AuthErrors.accountSuspended(),
            audit: {
              ctx: toFailureAuditContext({
                tenantId: tenant.id,
                userId: resolvedEntry.user?.id,
                membershipId: resolvedEntry.membership?.id,
              }),
              payload: { provider: params.provider, reason: 'membership_suspended', emailKey },
            },
          });

        case 'ACTIVE_MEMBERSHIP':
          if (!user || !membership) {
            throw AppError.internal('Active membership decision missing resolved entities.');
          }
          break;

        case 'PUBLIC_SIGNUP_ALLOWED':
        case 'INVITED_VALID':
        case 'INVITED_PENDING_ACTIVATION': {
          const role =
            resolvedEntry.membership?.role ??
            resolvedEntry.invite?.role ??
            (resolvedEntry.decision.code === 'PUBLIC_SIGNUP_ALLOWED' ? 'MEMBER' : null);

          if (!role) {
            throw AppError.internal('Invite-driven SSO activation missing role context.');
          }

          if (resolvedEntry.decision.code === 'INVITED_VALID' && resolvedEntry.invite) {
            const accepted = await inviteRepo.markAccepted({
              inviteId: resolvedEntry.invite.id,
              usedAt: now,
            });

            if (!accepted) {
              throw new SsoDeniedError({
                appError: AuthErrors.noAccess(),
                audit: {
                  ctx: toFailureAuditContext({
                    tenantId: tenant.id,
                    userId: resolvedEntry.user?.id,
                    membershipId: resolvedEntry.membership?.id,
                  }),
                  payload: { provider: params.provider, reason: 'invite_state_changed', emailKey },
                },
              });
            }

            inviteAcceptedInThisFlow = true;
          }

          const provisionResult = await provisionUserToTenant({
            trx,
            userRepo,
            membershipRepo,
            email: normalizedEmail,
            name: identity.name ?? null,
            tenantId: tenant.id,
            role,
            now,
          });

          user = provisionResult.user;
          membership = provisionResult.membership;

          const fullAudit = audit.withContext({
            tenantId: tenant.id,
            userId: user.id,
            membershipId: membership.id,
          });

          if (inviteAcceptedInThisFlow && resolvedEntry.invite) {
            await auditInviteAccepted(fullAudit, {
              ...resolvedEntry.invite,
              status: 'ACCEPTED',
              usedAt: now,
            });
          }

          if (provisionResult.userCreated) {
            await auditUserCreated(fullAudit, { userId: user.id });
          }
          if (provisionResult.membershipCreated) {
            await auditMembershipCreated(fullAudit, {
              membershipId: membership.id,
              userId: user.id,
              role: membership.role,
            });
          }
          if (provisionResult.membershipActivated) {
            await auditMembershipActivated(fullAudit, {
              membershipId: membership.id,
              userId: user.id,
              role: membership.role,
            });
          }
          break;
        }

        default: {
          const _exhaustive: never = resolvedEntry.decision.code;
          void _exhaustive;
          throw new Error('Unhandled SSO tenant-entry policy.');
        }
      }

      if (!user || !membership) {
        throw AppError.internal('SSO callback completed without resolved user/membership.');
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
        await authRepo.insertSsoIdentity({
          userId: user.id,
          provider: params.provider,
          providerSubject: identity.sub,
        });
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
          status: membership.status,
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
