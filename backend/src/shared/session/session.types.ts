/**
 * src/shared/session/session.types.ts
 *
 * WHY:
 * - Defines the server-side session data model and cookie naming policy.
 * - Sessions are stored in Redis (via Cache) with a TTL.
 * - Each session belongs to exactly one user + one tenant + one membership.
 *
 * COOKIE NAMING POLICY (v2 CORRECTED — topology doc Section 2):
 * - Production:  __Host-sid
 *   The __Host- prefix is a browser security mechanism enforcing:
 *   (1) Secure=true required, (2) Path=/ required, (3) Domain must NOT be set.
 *   This makes the cookie strictly host-only — a session cookie on
 *   goodwill-ca.hubins.com CANNOT be read by acme.hubins.com.
 * - Development: sid
 *   __Host- requires Secure=true, which requires HTTPS. Local dev uses HTTP.
 *   Using sid in dev avoids the requirement and keeps the dev flow unblocked.
 * - NEVER set Domain. In multi-tenant subdomain architecture a .hubins.com
 *   domain cookie would be readable across all tenants. That is catastrophic.
 *
 * RULES:
 * - Session data must be JSON-serializable (stored in Redis as JSON string).
 * - Session cookie is HttpOnly, Secure (prod), SameSite=Strict.
 * - Never store passwords or tokens in session data.
 * - Use getSessionCookieName(isProduction) everywhere the cookie name is needed.
 */

export type SessionData = {
  userId: string;
  tenantId: string;
  tenantKey: string; // subdomain key — used by middleware for tenant safety check
  membershipId: string;
  role: 'ADMIN' | 'MEMBER';
  mfaVerified: boolean;
  emailVerified: boolean;
  createdAt: string; // ISO string (JSON-safe)
};

/** Dev cookie name: plain `sid`. Used when running without HTTPS. */
export const SESSION_COOKIE_DEV_NAME = 'sid';

/** Prod cookie name: `__Host-sid`. Enforces host-only binding + Secure. */
export const SESSION_COOKIE_PROD_NAME = '__Host-sid';

/**
 * Returns the correct session cookie name for the current environment.
 * Used by: set-session-cookie.ts (writes), session.middleware.ts (reads).
 */
export function getSessionCookieName(isProduction: boolean): string {
  return isProduction ? SESSION_COOKIE_PROD_NAME : SESSION_COOKIE_DEV_NAME;
}

/**
 * @deprecated Use getSessionCookieName(isProduction) instead.
 * Kept for backward compatibility with existing tests that reference SESSION_COOKIE_NAME.
 */
export const SESSION_COOKIE_NAME = SESSION_COOKIE_DEV_NAME;

/** SSO state cookie name (dev). SameSite=Lax — required for OAuth redirect pass-through. */
export const SSO_STATE_COOKIE_DEV_NAME = 'sso-state';

/** SSO state cookie name (prod). __Host- enforces host-only binding. */
export const SSO_STATE_COOKIE_PROD_NAME = '__Host-sso-state';

/** Returns the correct SSO state cookie name for the current environment. */
export function getSsoStateCookieName(isProduction: boolean): string {
  return isProduction ? SSO_STATE_COOKIE_PROD_NAME : SSO_STATE_COOKIE_DEV_NAME;
}

/**
 * Session prefix in Redis. Full key: `session:{sessionId}`.
 * Keeps session keys isolated from other cache entries.
 */
export const SESSION_KEY_PREFIX = 'session';

/**
 * User-sessions index prefix in Redis. Full key: `session:user:{userId}`.
 *
 * WHY:
 * - Redis has no safe "find all keys by pattern" at scale.
 * - Instead, SessionStore maintains a Redis SET per user that tracks all
 *   active session IDs for that user.
 * - Used by destroyAllForUser() when a credential changes (password reset,
 *   future: admin suspend, MFA revocation).
 */
export const SESSION_USER_INDEX_PREFIX = 'session:user';
