/**
 * backend/src/app/server.ts
 *
 * WHY:
 * - Builds the Fastify server and registers global plugins/hooks.
 * - Keeps "build app" separate from "start listening" (test-friendly).
 *
 * HOW TO USE:
 * - Called from src/index.ts
 * - Global request context is attached here (requestId + tenant key from URL).
 */

import Fastify from 'fastify';
import type { AppConfig } from './config';
import type { AppDeps } from './di';
import { logger } from '../shared/logger/logger';
import { registerRequestContext } from '../shared/http/request-context';
import { registerAuthContext } from '../shared/http/auth-context';

export async function buildServer(opts: { config: AppConfig; deps: AppDeps }) {
  const app = Fastify({
    logger: false,
  });

  registerRequestContext(app);
  registerAuthContext(app);

  app.get('/health', (req) => {
    return {
      ok: true,
      env: opts.config.nodeEnv,
      requestId: req.requestContext.requestId,
      tenantKey: req.requestContext.tenantKey,
    };
  });

  app.addHook('onRequest', (req, _reply, done) => {
    logger.info('request', {
      method: req.method,
      url: req.url,
      requestId: req.requestContext.requestId,
      host: req.requestContext.host,
      tenantKey: req.requestContext.tenantKey,
    });

    done();
  });

  return app;
}
