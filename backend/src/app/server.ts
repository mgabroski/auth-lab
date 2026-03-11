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
 */

import Fastify from 'fastify';
import * as Sentry from '@sentry/node';

import type { AppConfig } from './config';
import type { AppDeps } from './di';

import { registerAuthContext } from '../shared/http/auth-context';
import { registerErrorHandler } from '../shared/http/error-handler';
import { registerRequestContext } from '../shared/http/request-context';
import { withRequestContext } from '../shared/logger/with-context';
import { registerSessionMiddleware } from '../shared/session/session.middleware';
import { getSessionCookieName } from '../shared/session/session.types';

export async function buildServer(opts: { config: AppConfig; deps: AppDeps }) {
  const { config, deps } = opts;
  const isProduction = config.nodeEnv === 'production';

  if (config.sentryDsn) {
    Sentry.init({
      dsn: config.sentryDsn,
      environment: config.nodeEnv,
      release: process.env.SERVICE_VERSION,
    });
  }

  const app = Fastify({
    logger: false,
    trustProxy: true,
  });

  registerRequestContext(app);
  registerAuthContext(app);
  registerSessionMiddleware(app, deps.sessionStore, getSessionCookieName(isProduction));
  registerErrorHandler(app);

  app.addHook('onRequest', (req, _reply, done) => {
    withRequestContext(req).info('request', {
      flow: 'http.request',
      method: req.method,
      url: req.url,
    });
    done();
  });

  return app;
}
