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
 * - Later we will register module routes via app/routes.ts (Brick 0/next).
 */

import Fastify from 'fastify';

import type { AppConfig } from './config.js';
import { logger } from '../shared/logger/logger.js';
import { registerRequestContext } from '../shared/http/request-context';
import { registerAuthContext } from '../shared/http/auth-context';

export async function buildServer(opts: { config: AppConfig }) {
  const app = Fastify({
    logger: false, // we use our own Winston logger (matches architecture direction)
  });

  // Global context plugins (Brick 1)
  registerRequestContext(app);
  registerAuthContext(app); // stub for later bricks (auth attaches user + membership here)

  // Simple health endpoint (useful for dev + future deployments)
  app.get('/health', (req) => {
    return {
      ok: true,
      env: opts.config.nodeEnv,
      requestId: req.requestContext.requestId,
    };
  });

  // Basic request logging (now includes requestId + tenantKey/subdomain)
  app.addHook('onRequest', (req) => {
    logger.info('request', {
      method: req.method,
      url: req.url,
      requestId: req.requestContext.requestId,
      host: req.requestContext.host,
      tenantKey: req.requestContext.tenantKey,
    });
  });

  return app;
}
