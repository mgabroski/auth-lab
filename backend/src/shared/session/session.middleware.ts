/**
 * backend/src/shared/session/session.middleware.ts
 *
 * WHY:
 * - Reads session cookie on every request.
 * - If valid session exists, populates req.authContext.
 * - Enforces tenant safety: session.tenantKey must EXACTLY match request tenantKey.
 *
 * RULES:
 * - Best-effort: missing/invalid/expired/wrong-tenant => treat as unauthenticated.
 * - No business logic (just session → authContext mapping).
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { SessionStore } from './session.store';
import { SESSION_COOKIE_NAME } from './session.types';

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

    const requestTenantKey = req.requestContext?.tenantKey ?? null;
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
