/**
 * backend/src/shared/session/session.middleware.ts
 *
 * WHY:
 * - Reads session cookie on every request.
 * - If valid session exists, populates req.authContext (userId, membershipId, role).
 * - Does NOT throw if no session — endpoints decide if auth is required.
 * - Enforces tenant safety: session.tenantKey must EXACTLY match request tenantKey.
 *   If mismatched (including null vs. any value), the session is silently ignored
 *   (authContext stays null). This prevents a cookie from tenant-A being used
 *   on tenant-B or on a host with no tenant (e.g. localhost).
 *
 * TENANT SAFETY — ENFORCEMENT POINT (LOCKED):
 * This is the ONLY place where session ↔ tenant binding is enforced.
 * Do NOT add a second enforcement point elsewhere — that violates SRP
 * and creates two sources of truth that can drift.
 *
 * Enforcement rule:
 *   session.tenantKey MUST equal req.requestContext.tenantKey (exact string match).
 *   Any mismatch — including a set tenantKey against a null-tenantKey request —
 *   is silently treated as unauthenticated. No error is exposed to the caller.
 *
 * Tests: test/e2e/tenant-isolation.spec.ts
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

    // ── Tenant safety (LOCKED — enforced here and only here) ─────────────
    // A session is issued for exactly one tenant (session.tenantKey).
    // The request targets a tenant identified by req.requestContext.tenantKey.
    //
    // Rejection cases (all treated identically — silent, no error exposed):
    //   1. session.tenantKey = 'goodwill-ca', request tenantKey = 'goodwill-chi'
    //      → cross-tenant cookie reuse attempt
    //   2. session.tenantKey = 'goodwill-ca', request tenantKey = null
    //      → tenant cookie used on a non-tenant host (e.g. bare localhost)
    //
    // Allow case:
    //   session.tenantKey === requestTenantKey (exact match, both non-null)
    //
    // Note: session.tenantKey is always set (required by SessionData type).
    // Using strict equality covers all mismatch permutations without
    // conditional guards that could accidentally create bypass paths.
    const requestTenantKey = req.requestContext?.tenantKey ?? null;
    if (session.tenantKey !== requestTenantKey) {
      // Session belongs to a different tenant (or request has no tenant).
      // Treat as unauthenticated — do not populate authContext, do not throw.
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
