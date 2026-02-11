/**
 * backend/src/shared/http/auth-context.ts
 *
 * WHY:
 * - Authentication and access are separate concepts.
 * - After session middleware (Brick 7d), this is populated from server-side session.
 * - Before that, all fields are null (unauthenticated request).
 *
 * HOW IT WORKS:
 * 1. registerAuthContext() sets stub (all null) on every request.
 * 2. Session middleware (Brick 7d) overwrites with real values if valid cookie exists.
 * 3. Controllers/services read req.authContext to determine authentication state.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';

export type Role = 'ADMIN' | 'MEMBER';

export type AuthContext = {
  userId: string | null;
  membershipId: string | null;
  role: Role | null;

  // Session fields (populated by session middleware, Brick 7d)
  sessionId: string | null;
  mfaVerified: boolean;
  tenantId: string | null;
};

declare module 'fastify' {
  interface FastifyRequest {
    authContext: AuthContext;
  }
}

export function registerAuthContext(app: FastifyInstance) {
  app.decorateRequest('authContext', null);

  app.addHook('onRequest', (req: FastifyRequest, _reply, done) => {
    req.authContext = {
      userId: null,
      membershipId: null,
      role: null,
      sessionId: null,
      mfaVerified: false,
      tenantId: null,
    };

    done();
  });
}
