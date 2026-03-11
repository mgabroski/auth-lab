/**
 * backend/src/shared/session/set-session-cookie.ts
 *
 * WHY:
 * - Session cookie construction is not unique to AuthController.
 * - SSO (sso-callback), MFA verify, and logout all need to set or clear
 *   the same cookie with the same flags.
 * - Centralising here means the HttpOnly / SameSite=Strict / Secure (prod)
 *   rules are defined in one place and can never drift between controllers.
 *
 * COOKIE CONTRACT (v2 CORRECTED — topology doc Section 2.1):
 * - Production name: __Host-sid (enforced by getSessionCookieName)
 * - Dev name: sid
 * - HttpOnly: always true
 * - Secure: true in production (required by __Host- prefix), false in dev (HTTP)
 * - SameSite: Strict — always. All session-authenticated calls are same-site fetch().
 *   Cross-site navigations (e.g. SSO callback) do NOT need the session cookie —
 *   the session is created inside the callback handler, not read.
 * - Domain: INTENTIONALLY OMITTED — host-only binding.
 *   NEVER add domain: '.hubins.com'. That breaks __Host- and weakens isolation.
 * - Path: /
 *
 * RULES:
 * - No business logic here.
 * - No DB access here.
 * - isProduction is injected at construction time from config.nodeEnv.
 */

import type { FastifyReply } from 'fastify';
import { getSessionCookieName } from './session.types';

export function setSessionCookie(
  reply: FastifyReply,
  sessionId: string,
  isProduction: boolean,
  sessionTtlSeconds: number,
): void {
  const cookieName = getSessionCookieName(isProduction);
  const expires = new Date(Date.now() + sessionTtlSeconds * 1000).toUTCString();

  const parts = [
    `${cookieName}=${sessionId}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${sessionTtlSeconds}`,
    `Expires=${expires}`,
    // Domain intentionally omitted — host-only binding.
    // __Host- prefix enforces this in production.
    // NEVER add: Domain=.hubins.com
  ];

  if (isProduction) {
    parts.push('Secure');
  }

  reply.header('Set-Cookie', parts.join('; '));
}

export function clearSessionCookie(reply: FastifyReply, isProduction: boolean): void {
  const cookieName = getSessionCookieName(isProduction);

  // Max-Age=0 instructs the browser to delete the cookie immediately.
  const parts = [
    `${cookieName}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  ];

  if (isProduction) {
    parts.push('Secure');
  }

  reply.header('Set-Cookie', parts.join('; '));
}
