/**
 * backend/src/shared/db/seed/run-dev-seed.ts
 *
 * WHY:
 * - Provides an explicit, repeatable entry point for the canonical local seed.
 * - Lets engineers reseed auth fixtures without starting the full backend server.
 *
 * RULES:
 * - Development/test only. Never run this in production.
 * - Reads the same config/env values used by build-app so docs and runtime stay aligned.
 */

import { buildConfig } from '../../../app/config';
import { buildDeps } from '../../../app/di';
import { runDevSeed } from './dev-seed';
import { logger } from '../../logger/logger';

async function main(): Promise<void> {
  const config = buildConfig();

  if (config.nodeEnv === 'production') {
    throw new Error('Refusing to run dev seed in production.');
  }

  const deps = await buildDeps(config);

  try {
    await runDevSeed({
      db: deps.db,
      tokenHasher: deps.tokenHasher,
      passwordHasher: deps.passwordHasher,
      outboxRepo: deps.outboxRepo,
      outboxEncryption: deps.outboxEncryption,
      options: {
        tenantKey: config.seed.tenantKey,
        tenantName: config.seed.tenantName,
        adminEmail: config.seed.adminEmail,
        inviteTtlHours: config.seed.inviteTtlHours,
      },
    });

    logger.info('seed.cli.done', {
      flow: 'seed.dev.cli',
      tenantKey: config.seed.tenantKey,
      adminEmail: config.seed.adminEmail,
    });
  } finally {
    await deps.close();
  }
}

void main().catch((err: unknown) => {
  logger.error('seed.cli.failed', { err });
  process.exit(1);
});
