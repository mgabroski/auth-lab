/**
 * backend/src/shared/session/session.middleware.ts
 *
 * WHY:
 * - Reads session cookie on every request.
 * - If valid session exists, populates req.authContext (userId, membershipId, role).
 * - Does NOT throw if no session — endpoints decide if auth is required.
 * - Enforces tenant safety: session.tenantKey must match request tenantKey.
 *   If mismatched, the session is silently ignored (authContext stays null).
 *   This prevents a cookie obtained on tenant-A from being used on tenant-B.
 *
 * RULES:
 * - Runs AFTER requestContext and authContext hooks (needs both to exist).
 * - Best-effort: if cookie is missing/invalid/expired/wrong-tenant, authContext stays null.
 * - No business logic (just session → authContext mapping).
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { SessionStore } from './session.store';
import { SESSION_COOKIE_NAME } from './session.types';

/**
 * Parses a raw Cookie header into key-value pairs.
 * Handles the standard format: "key1=value1; key2=value2"
 */
function parseCookies(raw: string | undefined): Record<string, string> {
  if (!raw) return {};

  const cookies: Record<string, string> = {};
  for (const pair of raw.split(';')) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) continue;

    const key = pair.substring(0, eqIdx).trim();
    const value = pair.substring(eqIdx + 1).trim();
    if (key) cookies[key] = value;
  }
  return cookies;
}

export function registerSessionMiddleware(app: FastifyInstance, sessionStore: SessionStore): void {
  app.addHook('onRequest', async (req: FastifyRequest) => {
    const cookies = parseCookies(req.headers.cookie);
    const sessionId = cookies[SESSION_COOKIE_NAME];
    if (!sessionId) return;

    const session = await sessionStore.get(sessionId);
    if (!session) return;

    // ── Tenant safety ────────────────────────────────────
    // The session was created for a specific tenant (identified by tenantKey).
    // The current request targets a tenant identified by req.requestContext.tenantKey.
    // If they don't match, the cookie belongs to a different workspace —
    // silently ignore it (don't populate authContext, don't throw).
    const requestTenantKey = req.requestContext?.tenantKey ?? null;
    if (requestTenantKey && session.tenantKey && session.tenantKey !== requestTenantKey) {
      // Session belongs to a different tenant — treat as unauthenticated
      return;
    }

    req.authContext = {
      userId: session.userId,
      membershipId: session.membershipId,
      role: session.role,
      sessionId,
      mfaVerified: session.mfaVerified,
      tenantId: session.tenantId,
    };
  });
}
