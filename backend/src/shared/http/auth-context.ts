/**
 * backend/src/shared/http/auth-context.ts
 *
 * WHY:
 * - Authentication and access are separate concepts.
 * - After auth (later), we attach user + membership info into request context.
 * - This avoids passing userId/role through every function manually.
 *
 * HOW TO USE:
 * - Registered once in app/server.ts via registerAuthContext(app).
 * - For now it's a stub (Brick 1).
 * - Later (Auth brick): auth middleware sets req.authContext.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';

export type Role = 'ADMIN' | 'MEMBER';

export type AuthContext = {
  userId: string | null;
  membershipId: string | null;
  role: Role | null;
};

declare module 'fastify' {
  interface FastifyRequest {
    authContext: AuthContext;
  }
}

export function registerAuthContext(app: FastifyInstance) {
  app.decorateRequest('authContext', null);

  app.addHook('onRequest', (req: FastifyRequest) => {
    // Default empty state. Filled later after authentication + membership checks.
    req.authContext = {
      userId: null,
      membershipId: null,
      role: null,
    };
  });
}
