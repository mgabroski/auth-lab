/**
 * backend/src/app/build-app.ts
 *
 * WHY:
 * - Starts OutboxWorker in non-test environments.
 * - Ensures clean shutdown (stop worker before closing deps).
 *
 * RULES:
 * - Worker must not run in nodeEnv=test.
 * - Worker start is a lifecycle concern (belongs here), not in DI.
 */

import type { AppConfig } from './config';
import { buildDeps, type BuildDepsOverrides } from './di';
import { buildServer } from './server';
import { registerRoutes } from './routes';
import { runDevSeed } from '../shared/db/seed/dev-seed';
import { logger } from '../shared/logger/logger';

import { OutboxWorker } from '../shared/outbox/outbox.worker';

export async function buildApp(config: AppConfig, overrides: BuildDepsOverrides = {}) {
  const deps = await buildDeps(config, overrides);
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

  // Outbox worker (non-test only)
  const worker =
    config.nodeEnv === 'test'
      ? null
      : new OutboxWorker(
          {
            db: deps.db,
            outboxRepo: deps.outboxRepo,
            outboxEncryption: deps.outboxEncryption,
            emailAdapter: deps.emailAdapter,
            logger: deps.logger,
            tokenHasher: deps.tokenHasher,
          },
          {
            pollIntervalMs: config.outbox.pollIntervalMs,
            batchSize: config.outbox.batchSize,
            maxAttemptsDefault: config.outbox.maxAttempts,
          },
        );

  if (worker) worker.start();

  const close = async () => {
    if (worker) worker.stop();
    await app.close();
    await deps.close();
  };

  return { app, deps, close };
}
