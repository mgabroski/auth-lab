/**
 * backend/src/shared/http/auth-context.ts
 *
 * WHY:
 * - Authentication and access are separate concepts.
 * - After session middleware, this is populated from server-side session.
 * - Before that, all fields are null/false (unauthenticated request).
 *
 * RULES:
 * - Decorated on request for consistent typing.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';

export type Role = 'ADMIN' | 'MEMBER';

export type AuthContext = {
  userId: string | null;
  membershipId: string | null;
  role: Role | null;

  sessionId: string | null;
  mfaVerified: boolean;
  tenantId: string | null;
  emailVerified: boolean;
};

declare module 'fastify' {
  interface FastifyRequest {
    authContext: AuthContext;
  }
}

export function registerAuthContext(app: FastifyInstance) {
  app.decorateRequest('authContext', null as unknown as AuthContext);

  app.addHook('onRequest', (req: FastifyRequest, _reply, done) => {
    req.authContext = {
      userId: null,
      membershipId: null,
      role: null,
      sessionId: null,
      mfaVerified: false,
      tenantId: null,
      emailVerified: false,
    };

    done();
  });
}
