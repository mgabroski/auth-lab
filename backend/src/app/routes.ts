/**
 * backend/src/app/routes.ts
 *
 * WHY:
 * - Central place to register all routes:
 *   - core routes (/health)
 *   - module routes later (auth, users, memberships, etc.)
 *
 * RULES:
 * - No business logic here.
 * - Only wiring: app.get/post + handler functions.
 */

import type { FastifyInstance } from 'fastify';

import type { AppConfig } from './config';
import type { AppDeps } from './di';

export function registerRoutes(app: FastifyInstance, opts: { config: AppConfig; deps: AppDeps }) {
  // Core health endpoint (E2E smoke + platform checks)
  app.get('/health', (req) => {
    return {
      ok: true,
      env: opts.config.nodeEnv,
      service: opts.config.serviceName,
      requestId: req.requestContext.requestId,
      tenantKey: req.requestContext.tenantKey,
    };
  });

  // Module routes
  opts.deps.invites.registerRoutes(app);

  // Future:
  // opts.deps.tenants.registerRoutes(app);
  // app.register(authRoutes, { prefix: '/api/auth', deps: opts.deps });
}
