/**
 * backend/src/shared/session/set-session-cookie.ts
 *
 * WHY:
 * - Session cookie construction is not unique to AuthController.
 * - SSO (Brick 10), MFA verify (Brick 9), and logout (Brick 13) all need to
 *   set or clear the same cookie with the same flags.
 * - Centralising here means the HttpOnly / SameSite=Strict / Secure (prod)
 *   rules are defined in one place and can never drift between controllers.
 *
 * RULES:
 * - No business logic here.
 * - No DB access here.
 * - Receives isProduction from the caller (injected at construction time in each controller).
 */

import type { FastifyReply } from 'fastify';
import { SESSION_COOKIE_NAME } from './session.types';

export function setSessionCookie(
  reply: FastifyReply,
  sessionId: string,
  isProduction: boolean,
): void {
  const parts = [`${SESSION_COOKIE_NAME}=${sessionId}`, 'Path=/', 'HttpOnly', 'SameSite=Strict'];

  if (isProduction) {
    parts.push('Secure');
  }

  reply.header('Set-Cookie', parts.join('; '));
}

export function clearSessionCookie(reply: FastifyReply, isProduction: boolean): void {
  // Max-Age=0 instructs the browser to delete the cookie immediately.
  const parts = [`${SESSION_COOKIE_NAME}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];

  if (isProduction) {
    parts.push('Secure');
  }

  reply.header('Set-Cookie', parts.join('; '));
}
