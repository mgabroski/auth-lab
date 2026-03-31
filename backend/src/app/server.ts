/**
 * backend/src/app/server.ts
 *
 * WHY:
 * - Builds the Fastify application.
 * - Registers global hooks/middleware once.
 * - Keeps server construction separate from route registration (test-friendly).
 *
 * RULES:
 * - No routes here. routes.ts owns endpoint registration.
 * - No module business logic here.
 * - Only app-wide infrastructure wiring belongs here.
 *
 * TOPOLOGY:
 * - CORS is intentionally not enabled.
 * - Browser traffic is same-origin through the reverse proxy.
 * - The backend is expected to run behind a trusted proxy boundary.
 *
 * TRUST PROXY:
 * - trustProxy: true is required so Fastify resolves req.ip from the
 *   forwarded chain rather than the proxy/container socket address.
 * - This is load-bearing for request context, rate limiting, and audit fidelity.
 *
 * STAGE 3:
 * - Emits x-request-id on every response so operators can correlate browser/SSR
 *   failures with backend logs.
 * - Adds request.started / request.completed structured logs.
 * - Records low-cardinality request totals + duration metrics.
 */

import Fastify from 'fastify';
import * as Sentry from '@sentry/node';

import type { AppConfig } from './config';
import type { AppDeps } from './di';

import { registerAuthContext } from '../shared/http/auth-context';
import { registerErrorHandler } from '../shared/http/error-handler';
import { registerRequestContext } from '../shared/http/request-context';
import {
  normalizeMetricRouteFromUrl,
  recordHttpRequestCompleted,
} from '../shared/observability/metrics';
import { withRequestContext } from '../shared/logger/with-context';
import { registerSessionMiddleware } from '../shared/session/session.middleware';
import { getSessionCookieName } from '../shared/session/session.types';

declare module 'fastify' {
  interface FastifyRequest {
    observedAtMs: number;
  }
}

const serviceVersion = process.env.SERVICE_VERSION ?? 'dev';

export async function buildServer(opts: { config: AppConfig; deps: AppDeps }) {
  const { config, deps } = opts;
  const isProduction = config.nodeEnv === 'production';

  if (config.sentryDsn) {
    Sentry.init({
      dsn: config.sentryDsn,
      environment: config.nodeEnv,
      release: serviceVersion,
    });
  }

  const app = Fastify({
    logger: false,
    trustProxy: true,
  });

  app.decorateRequest('observedAtMs', 0);

  registerRequestContext(app);
  registerAuthContext(app);
  registerSessionMiddleware(app, deps.sessionStore, getSessionCookieName(isProduction));
  registerErrorHandler(app);

  app.addHook('onRequest', (req, reply, done) => {
    req.observedAtMs = Date.now();

    const requestId = req.requestContext?.requestId;
    if (requestId) {
      reply.header('x-request-id', requestId);
    }

    withRequestContext(req).info('request.started', {
      event: 'request.started',
      flow: 'http.request',
      method: req.method,
      path: req.url,
      route: normalizeMetricRouteFromUrl(req.url),
      release: serviceVersion,
    });

    done();
  });

  app.addHook('onResponse', (req, reply, done) => {
    const durationMs = Math.max(0, Date.now() - (req.observedAtMs || Date.now()));
    const route = normalizeMetricRouteFromUrl(req.url);

    recordHttpRequestCompleted({
      method: req.method,
      route,
      statusCode: reply.statusCode,
      durationMs,
    });

    withRequestContext(req).info('request.completed', {
      event: 'request.completed',
      flow: 'http.request',
      method: req.method,
      path: req.url,
      route,
      statusCode: reply.statusCode,
      durationMs,
      release: serviceVersion,
    });

    done();
  });

  return app;
}
