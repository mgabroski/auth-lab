/**
 * backend/src/shared/db/seed/run-seed-e2e-fixtures.ts
 *
 * WHY:
 * - CLI entry point for the E2E fixture seeder.
 * - Called by: `yarn workspace @auth-lab/backend db:seed:e2e`
 * - In CI: called via `docker compose exec -T backend yarn workspace @auth-lab/backend db:seed:e2e`
 *   after the stack is healthy so the dev seed has already run.
 *
 * RULES:
 * - Never run in production (guarded below).
 * - Requires DATABASE_URL to be set (same as any other backend script).
 */

import { buildConfig } from '../../../app/config';
import { buildDeps } from '../../../app/di';
import { seedE2eFixtures } from './seed-e2e-fixtures';
import { logger } from '../../logger/logger';

async function main(): Promise<void> {
  const config = buildConfig();

  if (config.nodeEnv === 'production') {
    throw new Error('Refusing to run E2E fixture seed in production.');
  }

  const deps = await buildDeps(config);

  try {
    await seedE2eFixtures({
      db: deps.db,
      passwordHasher: deps.passwordHasher,
    });

    logger.info('seed.e2e.cli.done', {
      flow: 'seed.e2e.cli',
      message: 'E2E fixture seeding completed successfully.',
    });
  } finally {
    await deps.close();
  }
}

void main().catch((err: unknown) => {
  logger.error('seed.e2e.cli.failed', { err });
  process.exit(1);
});
