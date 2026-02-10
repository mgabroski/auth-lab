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
 */

import Fastify from 'fastify';
import type { AppConfig } from './config';
import type { AppDeps } from './di';
import { registerRequestContext } from '../shared/http/request-context';
import { registerAuthContext } from '../shared/http/auth-context';
import { registerErrorHandler } from '../shared/http/error-handler';
import { withRequestContext } from '../shared/logger/with-context';

export async function buildServer(_opts: { config: AppConfig; deps: AppDeps }) {
  const app = Fastify({
    logger: false,
  });

  registerRequestContext(app);
  registerAuthContext(app);
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
