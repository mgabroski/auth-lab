/**
 * backend/src/modules/auth/auth.service.ts
 *
 * WHY:
 * - Thin facade that dispatches to flow functions.
 *
 * RULES:
 * - No transactions here; flows own orchestration boundaries.
 * - No business logic here; flows/policies own logic.
 */

import type { DbExecutor } from '../../shared/db/db';
import type { TokenHasher } from '../../shared/security/token-hasher';
import type { PasswordHasher } from '../../shared/security/password-hasher';
import type { Logger } from '../../shared/logger/logger';
import type { RateLimiter } from '../../shared/security/rate-limit';
import type { AuditRepo } from '../../shared/audit/audit.repo';
import type { SessionStore } from '../../shared/session/session.store';
import type { Queue } from '../../shared/messaging/queue';

// Outbox (PR2)
import type { OutboxRepo } from '../../shared/outbox/outbox.repo';
import type { OutboxEncryption } from '../../shared/outbox/outbox-encryption';

import type { UserRepo } from '../users/dal/user.repo';
import type { MembershipRepo } from '../memberships/dal/membership.repo';

import type { TotpService } from '../../shared/security/totp';
import type { EncryptionService } from '../../shared/security/encryption';
import type { KeyedHasher } from '../../shared/security/keyed-hasher';

import type { AuthResult } from './auth.types';

import type { AuthRepo } from './dal/auth.repo';
import type { MfaRepo } from './dal/mfa.repo';
import type { EmailVerificationRepo } from './dal/email-verification.repo';

import type { RegisterParams } from './flows/register/execute-register-flow';
import { executeRegisterFlow } from './flows/register/execute-register-flow';

import type { LoginParams } from './flows/login/execute-login-flow';
import { executeLoginFlow } from './flows/login/execute-login-flow';

import type { RequestPasswordResetParams } from './flows/password-reset/request-password-reset-flow';
import { requestPasswordResetFlow } from './flows/password-reset/request-password-reset-flow';

import type { ResetPasswordParams } from './flows/password-reset/reset-password-flow';
import { resetPasswordFlow } from './flows/password-reset/reset-password-flow';

import { setupMfaFlow } from './flows/mfa/setup-mfa-flow';
import { verifyMfaSetupFlow } from './flows/mfa/verify-mfa-setup-flow';
import { verifyMfaFlow } from './flows/mfa/verify-mfa-flow';
import { recoverMfaFlow } from './flows/mfa/recover-mfa-flow';

import type { SsoProvider } from './helpers/sso-state';
import { buildSsoAuthorizationUrl } from './helpers/sso-authorize-url';
import { AUTH_RATE_LIMITS } from './auth.constants';

import { executeSsoCallbackFlow } from './flows/sso/execute-sso-callback-flow';
import type { SsoProviderRegistry } from './sso/sso-provider-registry';

import type { SignupParams } from './flows/signup/execute-signup-flow';
import { executeSignupFlow } from './flows/signup/execute-signup-flow';

import type { VerifyEmailParams } from './flows/signup/execute-verify-email-flow';
import { executeVerifyEmailFlow } from './flows/signup/execute-verify-email-flow';

import type { ResendVerificationParams } from './flows/signup/execute-resend-verification-flow';
import { executeResendVerificationFlow } from './flows/signup/execute-resend-verification-flow';

import { AuditWriter } from '../../shared/audit/audit.writer';
import { auditLogout } from './auth.audit';

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

      /**
       * Legacy queue: kept wired to avoid unrelated churn.
       * PR2 migrates auth/invite EMAIL side-effects to DB Outbox.
       */
      queue: Queue;

      // Outbox (PR2)
      outboxRepo: OutboxRepo;
      outboxEncryption: OutboxEncryption;

      userRepo: UserRepo;
      membershipRepo: MembershipRepo;
      authRepo: AuthRepo;
      mfaRepo: MfaRepo;
      emailVerificationRepo: EmailVerificationRepo;
      totpService: TotpService;
      encryptionService: EncryptionService;
      mfaKeyedHasher: KeyedHasher;

      // SSO
      sso: {
        stateEncryptionService: EncryptionService;
        redirectBaseUrl: string;
        providerRegistry: SsoProviderRegistry;
      };
    },
  ) {}

  /**
   * SSO: Build provider authorization redirect URL.
   * Rate limited early (per IP).
   */
  async startSso(input: {
    tenantKey: string;
    provider: SsoProvider;
    requestId: string;
    returnTo?: string;
    ip: string;
  }): Promise<{ redirectTo: string }> {
    // PII SAFETY: never store raw IP in cache keys (hash first).
    const ipKey = this.deps.tokenHasher.hash(input.ip);

    await this.deps.rateLimiter.hitOrThrow({
      key: `sso-start:ip:${ipKey}`,
      ...AUTH_RATE_LIMITS.ssoStart.perIp,
    });

    const redirectTo = buildSsoAuthorizationUrl({
      provider: input.provider,
      tenantKey: input.tenantKey,
      requestId: input.requestId,
      returnTo: input.returnTo,
      encryptionService: this.deps.sso.stateEncryptionService,
      redirectBaseUrl: this.deps.sso.redirectBaseUrl,
      providerRegistry: this.deps.sso.providerRegistry,
    });

    return { redirectTo };
  }

  async handleSsoCallback(input: {
    tenantKey: string | null;
    provider: SsoProvider;
    code: string;
    state: string;
    ip: string;
    userAgent: string | null;
    requestId: string;
  }): Promise<{ sessionId: string; redirectTo: string }> {
    return executeSsoCallbackFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        userRepo: this.deps.userRepo,
        membershipRepo: this.deps.membershipRepo,
        authRepo: this.deps.authRepo,
        sso: {
          stateEncryptionService: this.deps.sso.stateEncryptionService,
          redirectBaseUrl: this.deps.sso.redirectBaseUrl,
          providerRegistry: this.deps.sso.providerRegistry,
        },
      },
      {
        tenantKey: input.tenantKey,
        provider: input.provider,
        code: input.code,
        state: input.state,
        ip: input.ip,
        userAgent: input.userAgent,
        requestId: input.requestId,
      },
    );
  }

  async register(params: RegisterParams): Promise<{ result: AuthResult; sessionId: string }> {
    return executeRegisterFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        passwordHasher: this.deps.passwordHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        queue: this.deps.queue,
        userRepo: this.deps.userRepo,
        membershipRepo: this.deps.membershipRepo,
        authRepo: this.deps.authRepo,
      },
      params,
    );
  }

  async login(params: LoginParams): Promise<{ result: AuthResult; sessionId: string }> {
    return executeLoginFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        passwordHasher: this.deps.passwordHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
      },
      params,
    );
  }

  async requestPasswordReset(params: RequestPasswordResetParams): Promise<void> {
    return requestPasswordResetFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        authRepo: this.deps.authRepo,
        outboxRepo: this.deps.outboxRepo,
        outboxEncryption: this.deps.outboxEncryption,
      },
      params,
    );
  }

  async resetPassword(params: ResetPasswordParams): Promise<void> {
    return resetPasswordFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        passwordHasher: this.deps.passwordHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        authRepo: this.deps.authRepo,
      },
      params,
    );
  }

  async setupMfa(params: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    requestId: string;
    ip: string;
    userAgent: string | null;
  }): Promise<{ secret: string; qrCodeUri: string; recoveryCodes: string[] }> {
    return setupMfaFlow({
      deps: {
        db: this.deps.db,
        auditRepo: this.deps.auditRepo,
        mfaRepo: this.deps.mfaRepo,
        totpService: this.deps.totpService,
        encryptionService: this.deps.encryptionService,
        mfaKeyedHasher: this.deps.mfaKeyedHasher,
      },
      input: params,
    });
  }

  /**
   * MFA setup verification elevates privilege: mfaVerified false → true.
   * We rotate the session ID to reduce session fixation risk.
   */
  async verifyMfaSetup(params: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    code: string;
    requestId: string;
    ip: string;
    userAgent: string | null;
  }): Promise<{ status: 'AUTHENTICATED'; nextAction: 'NONE'; sessionId: string }> {
    return verifyMfaSetupFlow({
      deps: {
        db: this.deps.db,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        mfaRepo: this.deps.mfaRepo,
        totpService: this.deps.totpService,
        encryptionService: this.deps.encryptionService,
      },
      input: params,
    });
  }

  /**
   * MFA verification elevates privilege: mfaVerified false → true.
   * We rotate the session ID to reduce session fixation risk.
   */
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
  }): Promise<{ status: 'AUTHENTICATED'; nextAction: 'NONE'; sessionId: string }> {
    return verifyMfaFlow({
      deps: {
        db: this.deps.db,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        rateLimiter: this.deps.rateLimiter,
        totpService: this.deps.totpService,
        encryptionService: this.deps.encryptionService,
      },
      input: params,
    });
  }

  /**
   * MFA recovery elevates privilege: mfaVerified false → true.
   * We rotate the session ID to reduce session fixation risk.
   */
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
  }): Promise<{ status: 'AUTHENTICATED'; nextAction: 'NONE'; sessionId: string }> {
    return recoverMfaFlow({
      deps: {
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        rateLimiter: this.deps.rateLimiter,
        mfaRepo: this.deps.mfaRepo,
        mfaKeyedHasher: this.deps.mfaKeyedHasher,
      },
      input: params,
    });
  }

  async signup(params: SignupParams): Promise<{ result: AuthResult; sessionId: string }> {
    return executeSignupFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        passwordHasher: this.deps.passwordHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        sessionStore: this.deps.sessionStore,
        userRepo: this.deps.userRepo,
        membershipRepo: this.deps.membershipRepo,
        authRepo: this.deps.authRepo,
        emailVerificationRepo: this.deps.emailVerificationRepo,
        outboxRepo: this.deps.outboxRepo,
        outboxEncryption: this.deps.outboxEncryption,
      },
      params,
    );
  }

  async verifyEmail(params: VerifyEmailParams): Promise<{ status: 'VERIFIED' }> {
    return executeVerifyEmailFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        auditRepo: this.deps.auditRepo,
        emailVerificationRepo: this.deps.emailVerificationRepo,
        sessionStore: this.deps.sessionStore,
      },
      params,
    );
  }

  async resendVerification(params: ResendVerificationParams): Promise<void> {
    return executeResendVerificationFlow(
      {
        db: this.deps.db,
        tokenHasher: this.deps.tokenHasher,
        logger: this.deps.logger,
        rateLimiter: this.deps.rateLimiter,
        emailVerificationRepo: this.deps.emailVerificationRepo,
        outboxRepo: this.deps.outboxRepo,
        outboxEncryption: this.deps.outboxEncryption,
      },
      params,
    );
  }

  /**
   * Destroys the Redis session and writes a best-effort audit event.
   * Audit failure MUST NOT surface as 500 — caller always gets a clean return.
   */
  async logout(params: {
    sessionId: string;
    userId: string;
    tenantId: string;
    membershipId: string;
    ip: string;
    userAgent: string | null;
    requestId: string;
  }): Promise<void> {
    await this.deps.sessionStore.destroy(params.sessionId);

    // Audit is best-effort: failure must not surface as a 500.
    const audit = new AuditWriter(this.deps.auditRepo, {
      requestId: params.requestId,
      ip: params.ip,
      userAgent: params.userAgent,
    }).withContext({
      userId: params.userId,
      tenantId: params.tenantId,
      membershipId: params.membershipId,
    });

    try {
      await auditLogout(audit, { sessionId: params.sessionId });
    } catch (err) {
      this.deps.logger.error({
        msg: 'auth.logout.audit_failed',
        requestId: params.requestId,
        userId: params.userId,
        tenantId: params.tenantId,
        err,
      });
    }
  }
}
