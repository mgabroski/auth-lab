/**
 * src/modules/auth/auth.controller.ts
 *
 * WHY:
 * - Maps HTTP → service call for all auth endpoints.
 * - Sets session cookie on success (register, login, signup).
 * - Returns structured response.
 *
 * RULES:
 * - No DB access here.
 * - No business rules here.
 * - Cookie logic lives in shared/session/set-session-cookie (DRY).
 *
 * MFA — emailVerified gates (X1):
 * - /auth/mfa/setup:        requireEmailVerified: true
 * - /auth/mfa/verify-setup: requireEmailVerified: true
 * - /auth/mfa/verify:       requireEmailVerified: true
 * - /auth/mfa/recover:      requireEmailVerified: true
 *
 * Deliberately NOT gated by requireEmailVerified:
 * - /auth/verify-email:        IS the verification flow itself.
 * - /auth/resend-verification: IS the verification flow itself.
 * - /auth/logout:              trapping an unverified user from logging out
 *                              creates a support burden with zero security benefit.
 *
 * Public Signup + Email Verification:
 * - /auth/signup: session required = false (unauthenticated endpoint)
 * - /auth/verify-email: session required (user authenticated after signup)
 * - /auth/resend-verification: session required (user authenticated after signup)
 *
 * STAGE 1:
 * - /auth/me: session required (any valid session)
 * - /auth/config: public endpoint for frontend bootstrap
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  mfaCodeSchema,
  mfaRecoverSchema,
  ssoProviderSchema,
  signupSchema,
  verifyEmailSchema,
} from './auth.schemas';
import { AppError } from '../../shared/http/errors';
import type { AuthService } from './auth.service';
import { setSessionCookie, clearSessionCookie } from '../../shared/session/set-session-cookie';
import { requireSession } from '../../shared/http/require-auth-context';

const FORGOT_PASSWORD_RESPONSE = {
  message: 'If an account with that email exists, a password reset link has been sent.',
} as const;

const RESET_PASSWORD_RESPONSE = {
  message: 'Password updated successfully. Please sign in with your new password.',
} as const;

const RESEND_VERIFICATION_RESPONSE = {
  message: 'If your email is unverified, a new verification link has been sent.',
} as const;

function requireTenantKey(tenantKey: string | null | undefined): string {
  if (!tenantKey) {
    throw AppError.validationError('Missing tenant context');
  }
  return tenantKey;
}

/**
 * Guards against open-redirect attacks on the post-SSO returnTo parameter.
 *
 * Accepts only relative paths (start with '/') that are NOT protocol-relative
 * URLs (start with '//'). This ensures the browser is always redirected within
 * the same origin and can never be sent to an attacker-controlled domain.
 *
 * Examples:
 *   '/dashboard'          → safe   (relative path)
 *   '/settings/profile'   → safe   (relative path)
 *   '//evil.com'          → unsafe (protocol-relative — treated as absolute)
 *   'https://evil.com'    → unsafe (absolute URL)
 *   'javascript:alert(1)' → unsafe (non-path string)
 */
function isSafeReturnTo(value: string): boolean {
  return value.startsWith('/') && !value.startsWith('//');
}

export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly isProduction: boolean,
    private readonly sessionTtlSeconds: number,
  ) {}

  async register(req: FastifyRequest, reply: FastifyReply) {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const { result, sessionId } = await this.authService.register({
      tenantKey: req.requestContext.tenantKey,
      email: parsed.data.email,
      password: parsed.data.password,
      name: parsed.data.name,
      inviteToken: parsed.data.inviteToken,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
    });

    setSessionCookie(reply, sessionId, this.isProduction, this.sessionTtlSeconds);
    return reply.status(201).send(result);
  }

  async login(req: FastifyRequest, reply: FastifyReply) {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const { result, sessionId } = await this.authService.login({
      tenantKey: req.requestContext.tenantKey,
      email: parsed.data.email,
      password: parsed.data.password,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
    });

    setSessionCookie(reply, sessionId, this.isProduction, this.sessionTtlSeconds);
    return reply.status(200).send(result);
  }

  async me(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req);
    const result = await this.authService.getMe(auth);
    return reply.status(200).send(result);
  }

  async config(req: FastifyRequest, reply: FastifyReply) {
    const result = await this.authService.getConfig(req.requestContext.tenantKey);
    return reply.status(200).send(result);
  }

  async forgotPassword(req: FastifyRequest, reply: FastifyReply) {
    const parsed = forgotPasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    await this.authService.requestPasswordReset({
      tenantKey: req.requestContext.tenantKey,
      email: parsed.data.email,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
    });

    return reply.status(200).send(FORGOT_PASSWORD_RESPONSE);
  }

  async resetPassword(req: FastifyRequest, reply: FastifyReply) {
    const parsed = resetPasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    await this.authService.resetPassword({
      tenantKey: req.requestContext.tenantKey,
      token: parsed.data.token,
      newPassword: parsed.data.newPassword,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
    });

    return reply.status(200).send(RESET_PASSWORD_RESPONSE);
  }

  // ─── MFA handlers ────────────────────────────────────────────────────────────
  // All four require emailVerified: true (X1).
  // verifyEmail / resendVerification / logout are deliberately excluded — see file header.

  async mfaSetup(req: FastifyRequest, reply: FastifyReply) {
    const session = requireSession(req, { requireEmailVerified: true });

    const result = await this.authService.setupMfa({
      sessionId: session.sessionId,
      userId: session.userId,
      tenantId: session.tenantId,
      membershipId: session.membershipId,
      requestId: req.requestContext.requestId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
    });

    return reply.status(200).send(result);
  }

  async mfaVerifySetup(req: FastifyRequest, reply: FastifyReply) {
    const session = requireSession(req, { requireEmailVerified: true });

    const parsed = mfaCodeSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const result = await this.authService.verifyMfaSetup({
      sessionId: session.sessionId,
      userId: session.userId,
      tenantId: session.tenantId,
      membershipId: session.membershipId,
      code: parsed.data.code,
      requestId: req.requestContext.requestId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
    });

    // Rotate session ID on privilege elevation (MFA verified).
    const { sessionId: newSessionId, ...body } = result;
    setSessionCookie(reply, newSessionId, this.isProduction, this.sessionTtlSeconds);

    return reply.status(200).send(body);
  }

  async mfaVerify(req: FastifyRequest, reply: FastifyReply) {
    const session = requireSession(req, { requireEmailVerified: true });

    const parsed = mfaCodeSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const result = await this.authService.verifyMfa({
      sessionId: session.sessionId,
      userId: session.userId,
      tenantId: session.tenantId,
      membershipId: session.membershipId,
      mfaVerified: session.mfaVerified,
      code: parsed.data.code,
      requestId: req.requestContext.requestId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
    });

    // Rotate session ID on privilege elevation (MFA verified).
    const { sessionId: newSessionId, ...body } = result;
    setSessionCookie(reply, newSessionId, this.isProduction, this.sessionTtlSeconds);

    return reply.status(200).send(body);
  }

  async mfaRecover(req: FastifyRequest, reply: FastifyReply) {
    const session = requireSession(req, { requireEmailVerified: true });

    const parsed = mfaRecoverSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const result = await this.authService.recoverMfa({
      sessionId: session.sessionId,
      userId: session.userId,
      tenantId: session.tenantId,
      membershipId: session.membershipId,
      mfaVerified: session.mfaVerified,
      recoveryCode: parsed.data.recoveryCode,
      requestId: req.requestContext.requestId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
    });

    // Rotate session ID on privilege elevation (MFA verified).
    const { sessionId: newSessionId, ...body } = result;
    setSessionCookie(reply, newSessionId, this.isProduction, this.sessionTtlSeconds);

    return reply.status(200).send(body);
  }

  // ─── SSO handlers ─────────────────────────────────────────────────────────────

  async ssoStart(req: FastifyRequest, reply: FastifyReply) {
    const providerRaw = (req.params as { provider?: unknown } | undefined)?.provider;
    const providerRawParsed = ssoProviderSchema.safeParse(providerRaw);
    if (!providerRawParsed.success) {
      throw AppError.validationError('Invalid SSO provider', { provider: providerRaw });
    }

    const query = req.query as { returnTo?: unknown };
    const rawReturnTo =
      typeof query.returnTo === 'string' && query.returnTo.length ? query.returnTo : undefined;

    // Silently drop unsafe values rather than rejecting the SSO flow entirely.
    // An invalid returnTo hint is not a reason to block login.
    const returnTo =
      rawReturnTo !== undefined && isSafeReturnTo(rawReturnTo) ? rawReturnTo : undefined;

    const { redirectTo } = await this.authService.startSso({
      tenantKey: requireTenantKey(req.requestContext.tenantKey),
      provider: providerRawParsed.data,
      requestId: req.requestContext.requestId,
      returnTo,
      ip: req.ip,
    });

    return reply.status(302).redirect(redirectTo);
  }

  async ssoCallback(req: FastifyRequest, reply: FastifyReply) {
    const providerRaw = (req.params as { provider?: unknown } | undefined)?.provider;
    const providerParsed = ssoProviderSchema.safeParse(providerRaw);
    if (!providerParsed.success) {
      throw AppError.validationError('Invalid SSO provider', { provider: providerRaw });
    }

    const q = req.query as { code?: unknown; state?: unknown };
    if (typeof q.code !== 'string' || !q.code.length) {
      throw AppError.validationError('Missing code parameter');
    }
    if (typeof q.state !== 'string' || !q.state.length) {
      throw AppError.validationError('Missing state parameter');
    }

    const { sessionId, redirectTo } = await this.authService.handleSsoCallback({
      tenantKey: req.requestContext.tenantKey,
      provider: providerParsed.data,
      code: q.code,
      state: q.state,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
    });

    setSessionCookie(reply, sessionId, this.isProduction, this.sessionTtlSeconds);
    return reply.status(302).redirect(redirectTo);
  }

  // ─── Signup + email verification handlers ─────────────────────────────────────

  /**
   * POST /auth/signup
   *
   * Unauthenticated — no requireSession call.
   * Creates a session on success (same as register/login).
   * Returns 201 with AuthResult + sets session cookie.
   */
  async signup(req: FastifyRequest, reply: FastifyReply) {
    const parsed = signupSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const { result, sessionId } = await this.authService.signup({
      tenantKey: req.requestContext.tenantKey,
      email: parsed.data.email,
      password: parsed.data.password,
      name: parsed.data.name,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
    });

    setSessionCookie(reply, sessionId, this.isProduction, this.sessionTtlSeconds);
    return reply.status(201).send(result);
  }

  /**
   * POST /auth/verify-email
   *
   * Requires an authenticated session (user signed up and has a session cookie).
   * Upgrades the existing server-side session (Redis) so emailVerified becomes true.
   * This removes the need for logout/login after verification.
   * Returns 200 { status: 'VERIFIED' } on success.
   *
   * NOT gated by requireEmailVerified — this IS the verification flow itself.
   */
  async verifyEmail(req: FastifyRequest, reply: FastifyReply) {
    const session = requireSession(req);

    const parsed = verifyEmailSchema.safeParse(req.body);
    if (!parsed.success) {
      throw AppError.validationError('Invalid request body', {
        issues: parsed.error.issues,
      });
    }

    const result = await this.authService.verifyEmail({
      sessionId: session.sessionId,
      sessionUserId: session.userId,
      tenantId: session.tenantId,
      membershipId: session.membershipId,
      token: parsed.data.token,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
    });

    return reply.status(200).send(result);
  }

  /**
   * POST /auth/resend-verification
   *
   * Requires an authenticated session.
   * Always returns 200 — never reveals rate-limit status or email_verified state.
   * No request body required.
   *
   * NOT gated by requireEmailVerified — this IS the verification flow itself.
   */
  async resendVerification(req: FastifyRequest, reply: FastifyReply) {
    const session = requireSession(req);

    await this.authService.resendVerification({
      sessionUserId: session.userId,
      tenantKey: requireTenantKey(req.requestContext.tenantKey),
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
    });

    return reply.status(200).send(RESEND_VERIFICATION_RESPONSE);
  }

  /**
   * POST /auth/logout
   *
   * Guard: requireSession only — no role, no MFA requirement, no emailVerified gate.
   * A user who has not yet verified email must still be able to log out;
   * gating on emailVerified would permanently trap unverified sessions.
   * This is a deliberate product decision — see file header for rationale.
   *
   * Flow:
   *   1. requireSession → 401 if no session
   *   2. authService.logout() — destroys Redis session + writes best-effort audit
   *   3. clearSessionCookie — Max-Age=0 instructs browser to delete immediately
   *   4. 200 { message: 'Logged out.' }
   */
  async logout(req: FastifyRequest, reply: FastifyReply) {
    const auth = requireSession(req);

    await this.authService.logout({
      sessionId: auth.sessionId,
      userId: auth.userId,
      tenantId: auth.tenantId,
      membershipId: auth.membershipId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      requestId: req.requestContext.requestId,
    });

    clearSessionCookie(reply, this.isProduction);
    return reply.status(200).send({ message: 'Logged out.' });
  }
}
