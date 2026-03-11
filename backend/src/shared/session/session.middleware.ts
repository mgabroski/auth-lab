/**
 * backend/src/shared/session/session.middleware.ts
 *
 * WHY:
 * - Reads the configured session cookie on every request.
 * - Resolves the server-side session from the session store.
 * - Populates req.authContext when a valid session is present.
 * - Enforces fail-closed tenant safety at the session boundary.
 *
 * RULES:
 * - Missing cookie => unauthenticated
 * - Missing/expired session => unauthenticated
 * - Session tenant mismatch => unauthenticated
 * - No business logic belongs here
 *
 * IMPORTANT:
 * - cookieName is injected by app bootstrap
 * - dev uses `sid`
 * - production uses `__Host-sid`
 * - this must match what set-session-cookie.ts writes
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';

import type { SessionStore } from './session.store';

function parseCookies(raw: string | undefined): Record<string, string> {
  if (!raw) return {};

  const cookies: Record<string, string> = {};

  for (const pair of raw.split(';')) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) continue;

    const key = pair.substring(0, eqIdx).trim();
    const value = pair.substring(eqIdx + 1).trim();

    if (key) {
      cookies[key] = value;
    }
  }

  return cookies;
}

export function registerSessionMiddleware(
  app: FastifyInstance,
  sessionStore: SessionStore,
  cookieName: string,
): void {
  app.addHook('onRequest', async (req: FastifyRequest) => {
    const cookies = parseCookies(req.headers.cookie);
    const sessionId = cookies[cookieName];

    if (!sessionId) {
      return;
    }

    const session = await sessionStore.get(sessionId);
    if (!session) {
      return;
    }

    const requestTenantKey = req.requestContext?.tenantKey ?? null;

    // Fail closed: a valid session from tenant A must never authenticate on tenant B.
    if (session.tenantKey !== requestTenantKey) {
      return;
    }

    req.authContext = {
      userId: session.userId,
      membershipId: session.membershipId,
      role: session.role,
      sessionId,
      mfaVerified: session.mfaVerified,
      tenantId: session.tenantId,
      emailVerified: session.emailVerified,
    };
  });
}
