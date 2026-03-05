/**
 * backend/src/app/server.ts
 *
 * WHY:
 * - Builds the Fastify server and registers global plugins/hooks.
 * - Keeps "build server" separate from "register routes" (test-friendly).
 *
 * RULES:
 * - No routes here (routes.ts owns endpoints).
 * - Global hooks only (context, auth context, error handler, logging).
 *
 * X10 UPDATE:
 * - Sentry is initialised here (before routes) when config.sentryDsn is set.
 * - When SENTRY_DSN is absent (dev, CI, test), Sentry.init() is never called
 *   and all Sentry SDK calls are safe no-ops — zero behavior change in those
 *   environments.
 */

import Fastify from 'fastify';
import * as Sentry from '@sentry/node';
import type { AppConfig } from './config';
import type { AppDeps } from './di';
import { registerRequestContext } from '../shared/http/request-context';
import { registerAuthContext } from '../shared/http/auth-context';
import { registerErrorHandler } from '../shared/http/error-handler';
import { registerSessionMiddleware } from '../shared/session/session.middleware';
import { withRequestContext } from '../shared/logger/with-context';

export async function buildServer(_opts: { config: AppConfig; deps: AppDeps }) {
  // X10: Initialise Sentry before the server starts accepting requests.
  // Only runs when SENTRY_DSN is explicitly configured (production).
  // In dev, CI, and test: sentryDsn is undefined → Sentry is never initialised
  // → captureException() is a safe no-op throughout the app lifecycle.
  if (_opts.config.sentryDsn) {
    Sentry.init({
      dsn: _opts.config.sentryDsn,
      environment: _opts.config.nodeEnv,
      release: process.env.SERVICE_VERSION,
    });
  }

  const app = Fastify({
    logger: false,
  });

  registerRequestContext(app);
  registerAuthContext(app);
  registerSessionMiddleware(app, _opts.deps.sessionStore);
  registerErrorHandler(app);

  // Global request log (observability)
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
