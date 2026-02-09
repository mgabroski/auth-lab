/**
 * backend/src/shared/logger/logger.ts
 *
 * WHY:
 * - Central logger instance (structured JSON logs).
 * - Keeps logging consistent across app/modules.
 * - Adds stable metadata (service, env) for CloudWatch querying.
 *
 * HOW TO USE:
 * - Import `logger` anywhere you need logs.
 * - Prefer using `withRequestContext(req)` when logging inside request handlers.
 * - Do not log raw Error objects only—pass `{ err }` so stack/message is preserved.
 */

import winston from 'winston';

const nodeEnv = process.env.NODE_ENV ?? 'development';
const service = process.env.SERVICE_NAME ?? 'auth-lab-backend';
const level = process.env.LOG_LEVEL ?? 'info';

export const logger = winston.createLogger({
  level,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }), // ensures Error.stack is serialized
    winston.format.json(),
  ),
  defaultMeta: {
    service,
    env: nodeEnv,
  },
  transports: [new winston.transports.Console()],
});
