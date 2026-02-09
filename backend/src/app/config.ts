/**
 * backend/src/app/config.ts
 *
 * WHY:
 * - Central place for env parsing + validation (12-factor friendly).
 * - Prevents "undefined env var" bugs at runtime.
 *
 * HOW TO USE:
 * - In dev, we load backend/.env via dotenv.
 * - In prod later, platform injects env vars (no file).
 */

import 'dotenv/config';
import { z } from 'zod';

const ConfigSchema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: z.coerce.number().default(3000),
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
});

export type AppConfig = {
  nodeEnv: string;
  port: number;
  databaseUrl: string;
  redisUrl: string;
};

export function buildConfig(): AppConfig {
  const parsed = ConfigSchema.parse(process.env);

  return {
    nodeEnv: parsed.NODE_ENV,
    port: parsed.PORT,
    databaseUrl: parsed.DATABASE_URL,
    redisUrl: parsed.REDIS_URL,
  };
}
