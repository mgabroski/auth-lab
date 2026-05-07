/**
 * backend/src/shared/session/set-cookie-header.ts
 *
 * WHY:
 * - Auth responses may need to emit more than one Set-Cookie header.
 * - Fastify's reply.header('Set-Cookie', value) can be easy to misuse because
 *   a later call may replace the earlier value depending on call shape.
 * - SSO callback is load-bearing: it sets the session cookie and clears the
 *   short-lived SSO state cookie in the same response.
 *
 * RULES:
 * - Cookie helpers append through this single function.
 * - No business logic here.
 * - No cookie policy decisions here; callers construct the cookie string.
 */

import type { FastifyReply } from 'fastify';

export function appendSetCookieHeader(reply: FastifyReply, cookieValue: string): void {
  const existing = reply.getHeader('Set-Cookie');

  if (existing === undefined) {
    reply.header('Set-Cookie', cookieValue);
    return;
  }

  if (Array.isArray(existing)) {
    reply.header('Set-Cookie', [...existing.map(String), cookieValue]);
    return;
  }

  reply.header('Set-Cookie', [String(existing), cookieValue]);
}
