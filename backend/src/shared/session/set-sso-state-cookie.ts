/**
 * backend/src/shared/session/set-sso-state-cookie.ts
 *
 * WHY:
 * - The SSO state cookie has a DIFFERENT policy than the session cookie.
 * - Keeping them in separate files prevents policy confusion and drift.
 * - Separation is locked in topology doc Section 2.1: "There are exactly
 *   two cookies in this system. They must never be confused."
 *
 * SSO STATE COOKIE CONTRACT (topology doc Section 2.1):
 * - Production name: __Host-sso-state
 * - Dev name: sso-state
 * - HttpOnly: always true
 * - Secure: true in production, false in dev (HTTP)
 * - SameSite: Lax — REQUIRED (Strict would break the OAuth redirect flow)
 *   The OAuth provider redirects back to our callback URL. This is a
 *   cross-site top-level navigation (Google → goodwill-ca.hubins.com).
 *   SameSite=Strict blocks this. Lax allows top-level navigations only.
 * - Domain: INTENTIONALLY OMITTED — host-only binding.
 * - Path: /
 * - Max-Age: 600 seconds (10 minutes) — short-lived by design.
 *   The SSO round-trip should complete in seconds; 10 min is a generous upper bound.
 *
 * WHY Lax is safe here:
 * - The cookie contains encrypted state only (no user data, no session identity).
 * - It is cleared immediately after the callback completes.
 * - Lax still blocks cross-site POST and cross-site subresource requests.
 *   It only allows top-level navigations, which is exactly what OAuth redirect is.
 *
 * RULES:
 * - No business logic here.
 * - No DB access here.
 * - isProduction is injected at call site from config.nodeEnv.
 */

import type { FastifyReply } from 'fastify';
import { getSsoStateCookieName } from './session.types';

/** SSO state cookie TTL: 10 minutes. Must exceed the OAuth provider round-trip. */
export const SSO_STATE_COOKIE_TTL_SECONDS = 600;

export function setSsoStateCookie(
  reply: FastifyReply,
  encryptedState: string,
  isProduction: boolean,
): void {
  const cookieName = getSsoStateCookieName(isProduction);
  const expires = new Date(Date.now() + SSO_STATE_COOKIE_TTL_SECONDS * 1000).toUTCString();

  const parts = [
    `${cookieName}=${encodeURIComponent(encryptedState)}`,
    'Path=/',
    'HttpOnly',
    // SameSite=Lax is REQUIRED — Strict blocks the OAuth redirect callback.
    // The provider (Google, Microsoft) redirects back as a cross-site navigation.
    'SameSite=Lax',
    `Max-Age=${SSO_STATE_COOKIE_TTL_SECONDS}`,
    `Expires=${expires}`,
    // Domain intentionally omitted — host-only binding.
  ];

  if (isProduction) {
    parts.push('Secure');
  }

  // Use append so we don't overwrite the session cookie if both are set
  // in the same response (should not happen, but safe).
  reply.header('Set-Cookie', parts.join('; '));
}

export function clearSsoStateCookie(reply: FastifyReply, isProduction: boolean): void {
  const cookieName = getSsoStateCookieName(isProduction);

  const parts = [
    `${cookieName}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  ];

  if (isProduction) {
    parts.push('Secure');
  }

  reply.header('Set-Cookie', parts.join('; '));
}

/**
 * Reads and decodes the SSO state cookie from an incoming request's Cookie header.
 *
 * WHY here: all SSO state cookie logic is co-located in this file.
 * Callers (controller) never hardcode cookie names or URL-decoding logic.
 *
 * Returns the raw encrypted state string, or null if the cookie is absent.
 */
export function readSsoStateCookie(
  rawCookieHeader: string | undefined,
  isProduction: boolean,
): string | null {
  if (!rawCookieHeader) return null;

  const cookieName = getSsoStateCookieName(isProduction);

  for (const pair of rawCookieHeader.split(';')) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) continue;
    const key = pair.substring(0, eqIdx).trim();
    const value = pair.substring(eqIdx + 1).trim();
    if (key === cookieName) {
      return decodeURIComponent(value);
    }
  }

  return null;
}
