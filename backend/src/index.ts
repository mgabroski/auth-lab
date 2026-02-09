/**
 * backend/src/index.ts
 *
 * WHY:
 * - Single entrypoint for the backend application.
 * - Keeps startup logic small: load config -> build server -> listen.
 *
 * HOW TO USE:
 * - Dev: `yarn dev` (runs via tsx watch)
 * - Later prod: `yarn build && yarn start` (runs dist/)
 */

import { buildConfig } from './app/config.js';
import { buildServer } from './app/server.js';
import { logger } from './shared/logger/logger.js';

async function main(): Promise<void> {
  const config = buildConfig();

  const app = await buildServer({ config });

  await app.listen({ port: config.port, host: '0.0.0.0' });

  logger.info('server.listening', {
    port: config.port,
    env: config.nodeEnv,
    service: config.serviceName,
  });
}

void main().catch((err: unknown) => {
  logger.error('server.fatal_startup_error', { err });
  process.exit(1);
});
