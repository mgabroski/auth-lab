/**
 * backend/src/app/routes.ts
 *
 * WHY:
 * - Central place to register all routes:
 * - core routes (/health)
 * - module routes later (auth, users, memberships, etc.)
 *
 * RULES:
 * - No business logic here.
 * - Only wiring: app.get/post + handler functions.
 *
 * X11 — Real DB + Redis liveness probe:
 * - Previously GET /health returned { ok: true } unconditionally.
 * Kubernetes readiness probes would route traffic to broken pods when DB or
 * Redis connections were dropped — the pod appeared healthy to k8s while being
 * completely unable to serve requests.
 * - Fix: perform a lightweight DB probe (SELECT 1, no table scan) and a Redis
 * probe (SET health:ping with a 5-second TTL). Return 503 if either fails so
 * k8s removes the pod from the load-balancer rotation automatically.
 * - The `checks` map is included in the response body so operators can see which
 * dependency failed without needing to read logs.
 * - Each probe is wrapped in an independent try/catch so a DB failure doesn't
 * prevent the Redis check from running (and vice versa).
 */

import type { FastifyInstance } from 'fastify';

import type { AppConfig } from './config';
import type { AppDeps } from './di';

export function registerRoutes(app: FastifyInstance, opts: { config: AppConfig; deps: AppDeps }) {
  // X11: Real infrastructure liveness probe.
  // Kubernetes readiness probe should target this endpoint.
  // 200 → pod is healthy, route traffic.
  // 503 → pod cannot reach DB or Redis, remove from rotation.
  app.get('/health', async (req, reply) => {
    const checks: Record<string, boolean> = {};
    const { db, cache } = opts.deps;

    // DB probe — lightweight SELECT 1 (no table scan, no index lookup).
    try {
      // Use the 'eb' (expression builder) object directly to avoid 'unbound-method' lint errors
      // on the 'lit' function.
      await db.selectNoFrom((eb) => [eb.lit(1).as('one')]).execute();
      checks.db = true;
    } catch {
      checks.db = false;
    }

    // Redis probe — write a short-lived key to confirm the connection is alive.
    // TTL of 5 seconds so test keys never accumulate.
    try {
      await cache.set('health:ping', '1', { ttlSeconds: 5 });
      checks.redis = true;
    } catch {
      checks.redis = false;
    }

    const healthy = Object.values(checks).every(Boolean);

    return reply.status(healthy ? 200 : 503).send({
      ok: healthy,
      env: opts.config.nodeEnv,
      service: opts.config.serviceName,
      requestId: req.requestContext.requestId,
      tenantKey: req.requestContext.tenantKey,
      checks,
    });
  });

  // Module routes
  opts.deps.invites.registerRoutes(app);
  opts.deps.auth.registerRoutes(app);
  opts.deps.audit.registerRoutes(app);
}
