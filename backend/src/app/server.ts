/**
 * backend/src/app/server.ts
 *
 * WHY:
 * - Builds the Fastify server and registers routes/plugins.
 * - Keeps "build app" separate from "start listening" (test-friendly).
 *
 * HOW TO USE:
 * - Called from src/index.ts
 * - Later we will register module routes via an app/routes.ts file.
 */

import Fastify from 'fastify';
import type { AppConfig } from './config.js';
import { logger } from '../shared/logger/logger.js';

export async function buildServer(opts: { config: AppConfig }) {
  const app = Fastify({
    logger: false, // we use our own Winston logger (matches architecture direction)
  });

  // Simple health endpoint (useful for dev + future deployments)
  app.get('/health', () => {
    return { ok: true, env: opts.config.nodeEnv };
  });

  // Basic request logging (minimal now; later we’ll add requestId + context)
  app.addHook('onRequest', (req) => {
    logger.info('request', { method: req.method, url: req.url });
  });

  return app;
}
