/**
 * backend/src/app/routes.ts
 *
 * WHY:
 * - Central route composition lives here.
 * - App bootstrap owns route registration order.
 * - Business logic does not belong here.
 *
 * CURRENT FOUNDATION SCOPE:
 * - core route: /health
 * - module routes: invites, auth, audit
 *
 * HEALTH ENDPOINT:
 * - This is a real readiness/liveness-style probe for local/devops use.
 * - It performs lightweight checks against DB and Redis.
 * - 200 means the app can currently reach its critical dependencies.
 * - 503 means the process is up but the app should not receive traffic.
 */

import type { FastifyInstance } from 'fastify';

import type { AppConfig } from './config';
import type { AppDeps } from './di';

export function registerRoutes(
  app: FastifyInstance,
  opts: { config: AppConfig; deps: AppDeps },
): void {
  const { config, deps } = opts;

  app.get('/health', async (req, reply) => {
    const checks: Record<string, boolean> = {};

    try {
      await deps.db.selectNoFrom((eb) => [eb.lit(1).as('one')]).execute();
      checks.db = true;
    } catch {
      checks.db = false;
    }

    try {
      await deps.cache.set('health:ping', '1', { ttlSeconds: 5 });
      checks.redis = true;
    } catch {
      checks.redis = false;
    }

    const healthy = Object.values(checks).every(Boolean);

    return reply.status(healthy ? 200 : 503).send({
      ok: healthy,
      env: config.nodeEnv,
      service: config.serviceName,
      requestId: req.requestContext.requestId,
      tenantKey: req.requestContext.tenantKey,
      checks,
    });
  });

  deps.invites.registerRoutes(app);
  deps.auth.registerRoutes(app);
  deps.audit.registerRoutes(app);
}
