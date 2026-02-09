/**
 * backend/src/app/build-app.ts
 *
 * WHY:
 * - Single place that assembles the runnable Fastify app:
 *   config -> deps -> server -> routes
 * - Makes E2E tests simple (build once, app.inject, close).
 * - Clean place to run dev-only seed/bootstrap later.
 *
 * RULES:
 * - No business logic here (only composition).
 * - No request handlers here (those belong in routes/modules).
 */

import type { AppConfig } from './config';
import { buildDeps } from './di';
import { buildServer } from './server';
import { registerRoutes } from './routes';
import { runDevSeed } from '../shared/db/seed/dev-seed';
import { logger } from '../shared/logger/logger';

export async function buildApp(config: AppConfig) {
  const deps = await buildDeps(config);
  const app = await buildServer({ config, deps });

  registerRoutes(app, { config, deps });

  // DEV-only seed bootstrap
  if (config.seed.enabled) {
    const flow = 'seed.dev';

    if (config.nodeEnv === 'production') {
      logger.warn('seed.skipped_in_production', { flow });
    } else {
      logger.info('seed.start', {
        flow,
        tenantKey: config.seed.tenantKey,
        adminEmail: config.seed.adminEmail,
      });

      await runDevSeed({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        options: {
          tenantKey: config.seed.tenantKey,
          tenantName: config.seed.tenantName,
          adminEmail: config.seed.adminEmail,
          inviteTtlHours: config.seed.inviteTtlHours,
        },
      });

      logger.info('seed.done', {
        flow,
        tenantKey: config.seed.tenantKey,
        adminEmail: config.seed.adminEmail,
      });
    }
  }

  const close = async () => {
    await app.close();
    await deps.close();
  };

  return { app, deps, close };
}
