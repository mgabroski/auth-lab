/**
 * backend/src/app/routes.ts
 *
 * WHY:
 * - Central route composition lives here.
 * - App bootstrap owns route registration order.
 * - Business logic does not belong here.
 *
 * CURRENT FOUNDATION SCOPE:
 * - core routes: /metrics, /health
 * - module routes: invites, auth, audit, settings
 * - CP routes: real /cp/accounts create/read/list plus Step 2 saves, review/publish, and status toggle
 *
 * HEALTH ENDPOINT:
 * - Real readiness/liveness-style probe for local/devops use.
 * - Performs lightweight checks against DB and Redis.
 * - 200 means the app can currently reach its critical dependencies.
 * - 503 means the process is up but the app should not receive traffic.
 *
 * METRICS ENDPOINT:
 * - Exposes low-cardinality Prometheus-text metrics for Stage 3.
 * - No vendor lock-in implied by the endpoint.
 *
 * CP ROUTE PREFIX:
 * - All Control Plane backend routes are registered under /cp/*.
 * - They are registered by deps.controlPlane.registerRoutes(app, config).
 * - CP_ENABLED controls whether the route surface exists.
 * - CP_AUTH_MODE controls access policy. Current local/CI mode is `none`;
 *   production must not use no-auth CP.
 */

import type { FastifyInstance } from 'fastify';

import type { AppConfig } from './config';
import type { AppDeps } from './di';

import { metricsContentType, renderMetricsSnapshot } from '../shared/observability/metrics';

export function registerRoutes(
  app: FastifyInstance,
  opts: { config: AppConfig; deps: AppDeps },
): void {
  const { config, deps } = opts;

  app.get('/metrics', async (_req, reply) => {
    return reply
      .header('content-type', metricsContentType)
      .header('cache-control', 'no-store')
      .status(200)
      .send(renderMetricsSnapshot());
  });

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
    const isProduction = config.nodeEnv === 'production';

    return reply.status(healthy ? 200 : 503).send({
      ok: healthy,
      env: config.nodeEnv,
      service: config.serviceName,
      checks,
      ...(!isProduction && {
        requestId: req.requestContext.requestId,
        tenantKey: req.requestContext.tenantKey,
      }),
    });
  });

  deps.invites.registerRoutes(app);
  deps.auth.registerRoutes(app);
  deps.audit.registerRoutes(app);
  deps.settings.registerRoutes(app);

  if (config.controlPlane.enabled) {
    deps.controlPlane.registerRoutes(app, config);
  }
}
