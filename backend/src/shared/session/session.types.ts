/**
 * backend/src/shared/session/session.types.ts
 *
 * WHY:
 * - Defines the server-side session data model.
 * - Sessions are stored in Redis (via Cache) with a TTL.
 * - Each session belongs to exactly one user + one tenant + one membership.
 * - mfaVerified starts false for users who require MFA; login is incomplete until true.
 *
 * RULES:
 * - Session data must be JSON-serializable (stored in Redis as JSON string).
 * - Session cookie is HttpOnly, Secure (prod), SameSite=Strict.
 * - Never store passwords or tokens in session data.
 */

export type SessionData = {
  userId: string;
  tenantId: string;
  tenantKey: string; // subdomain key — used by middleware for tenant safety check
  membershipId: string;
  role: 'ADMIN' | 'MEMBER';
  mfaVerified: boolean;
  createdAt: string; // ISO string (JSON-safe)
};

export const SESSION_COOKIE_NAME = 'sid';

/**
 * Session prefix in Redis. Full key: `session:{sessionId}`.
 * This keeps session keys isolated from other cache entries.
 */
export const SESSION_KEY_PREFIX = 'session';
