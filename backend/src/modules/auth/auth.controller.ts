/**
 * backend/src/modules/auth/auth.controller.ts
 *
 * WHY:
 * - Maps HTTP → service call for register and login.
 * - Sets session cookie on success.
 * - Returns structured response.
 *
 * RULES:
 * - No DB access here.
 * - No business rules here.
 * - Validate with Zod and throw AppError.
 */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { registerSchema, loginSchema } from './auth.schemas';
import { AppError } from '../../shared/http/errors';
import type { AuthService } from './auth.service';
import { SESSION_COOKIE_NAME } from '../../shared/session/session.types';

export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly isProduction: boolean,
  ) {}

  private setSessionCookie(reply: FastifyReply, sessionId: string): void {
    const parts = [`${SESSION_COOKIE_NAME}=${sessionId}`, 'Path=/', 'HttpOnly', 'SameSite=Strict'];

    if (this.isProduction) {
      parts.push('Secure');
    }

    reply.header('Set-Cookie', parts.join('; '));
  }

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

    this.setSessionCookie(reply, sessionId);

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

    this.setSessionCookie(reply, sessionId);

    return reply.status(200).send(result);
  }
}
