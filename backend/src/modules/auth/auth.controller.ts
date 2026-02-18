/**
 * src/modules/auth/auth.controller.ts
 *
 * WHY:
 * - Maps HTTP → service call for all auth endpoints.
 * - Sets session cookie on success (register, login).
 * - Returns structured response.
 *
 * RULES:
 * - No DB access here.
 * - No business rules here.
 * - Cookie logic lives in shared/session/set-session-cookie (DRY).
 *
 * MFA (Brick 9):
 * - /auth/mfa/setup: requires an authenticated session (from login/register)
 * - /auth/mfa/verify-setup: verifies the provisional secret and flips session.mfaVerified
 * - /auth/mfa/verify: verifies MFA for a partially authenticated session (mfaVerified=false)
 * - /auth/mfa/recover: uses a recovery code, flips session.mfaVerified
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  mfaCodeSchema,
  mfaRecoverSchema,
} from './auth.schemas';
import { AppError } from '../../shared/http/errors';
import type { AuthService } from './auth.service';
import { setSessionCookie } from '../../shared/session/set-session-cookie';
import { requireAuthContext } from '../../shared/http/require-auth-context';

const FORGOT_PASSWORD_RESPONSE = {
  message: 'If an account with that email exists, a password reset link has been sent.',
} as const;

const RESET_PASSWORD_RESPONSE = {
  message: 'Password updated successfully. Please sign in with your new password.',
} as const;

export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly isProduction: boolean,
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

    setSessionCookie(reply, sessionId, this.isProduction);
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

    setSessionCookie(reply, sessionId, this.isProduction);
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

  // ─────────────────────────────────────────────────────────────────────────────
  // MFA (Brick 9)
  // ─────────────────────────────────────────────────────────────────────────────

  async mfaSetup(req: FastifyRequest, reply: FastifyReply) {
    const session = requireAuthContext(req);

    const result = await this.authService.setupMfa({
      sessionId: session.sessionId,
      userId: session.userId,
      tenantId: session.tenantId, // ✅ needed for audit scope
      membershipId: session.membershipId, // ✅ needed for audit scope
      requestId: req.requestContext.requestId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
    });

    return reply.status(200).send(result);
  }

  async mfaVerifySetup(req: FastifyRequest, reply: FastifyReply) {
    const session = requireAuthContext(req);

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

    return reply.status(200).send(result);
  }

  async mfaVerify(req: FastifyRequest, reply: FastifyReply) {
    const session = requireAuthContext(req);

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

    return reply.status(200).send(result);
  }

  async mfaRecover(req: FastifyRequest, reply: FastifyReply) {
    const session = requireAuthContext(req);

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

    return reply.status(200).send(result);
  }
}
