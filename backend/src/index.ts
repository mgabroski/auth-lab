/**
 * backend/src/index.ts
 *
 * WHY:
 * - Single entrypoint for the backend application.
 * - Keeps startup logic small: load config -> build app -> listen.
 */

import { buildConfig } from './app/config';
import { buildApp } from './app/build-app';
import { logger } from './shared/logger/logger';

async function main(): Promise<void> {
  const config = buildConfig();
  const { app, close } = await buildApp(config);

  await app.listen({ port: config.port, host: '0.0.0.0' });

  logger.info('server.listening', {
    port: config.port,
    env: config.nodeEnv,
    service: config.serviceName,
  });

  const shutdown = async (signal: string) => {
    logger.info('server.shutdown', { signal });
    await close();
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

void main().catch((err: unknown) => {
  logger.error('server.fatal_startup_error', { err });
  process.exit(1);
});
