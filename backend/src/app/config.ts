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
 *
 * TYPING:
 * - nodeEnv is a union ('development' | 'test' | 'production'), not a plain string.
 *   This ensures that comparisons in di.ts (nodeEnv === 'test', nodeEnv === 'production')
 *   are exhaustive and that invalid values ('prod', 'staging') are caught at startup
 *   by Zod rather than silently falling through to the wrong branch.
 */

import 'dotenv/config';
import { z } from 'zod';

const NodeEnvSchema = z.enum(['development', 'test', 'production']).default('development');

const ConfigSchema = z.object({
  NODE_ENV: NodeEnvSchema,
  PORT: z.coerce.number().default(3000),

  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),

  // Logging / service identity
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly']).default('info'),
  SERVICE_NAME: z.string().default('auth-lab-backend'),

  BCRYPT_COST: z.coerce.number().int().min(10).max(15).default(12),

  // Session
  SESSION_TTL_SECONDS: z.coerce.number().int().min(300).max(604800).default(86400),

  // DEV seed bootstrap (idempotent)
  SEED_ON_START: z.coerce.boolean().default(false),
  SEED_TENANT_KEY: z.string().default('goodwill-ca'),
  SEED_TENANT_NAME: z.string().default('GoodWill California'),
  SEED_ADMIN_EMAIL: z.string().email().default('admin@example.com'),
  SEED_INVITE_TTL_HOURS: z.coerce
    .number()
    .int()
    .min(1)
    .max(24 * 30)
    .default(24 * 7),
});

export type NodeEnv = z.infer<typeof NodeEnvSchema>;

export type AppConfig = {
  nodeEnv: NodeEnv;
  port: number;
  databaseUrl: string;
  redisUrl: string;

  logLevel: string;
  serviceName: string;

  bcryptCost: number;

  sessionTtlSeconds: number;

  seed: {
    enabled: boolean;
    tenantKey: string;
    tenantName: string;
    adminEmail: string;
    inviteTtlHours: number;
  };
};

export function buildConfig(): AppConfig {
  const parsed = ConfigSchema.parse(process.env);

  return {
    nodeEnv: parsed.NODE_ENV,
    port: parsed.PORT,
    databaseUrl: parsed.DATABASE_URL,
    redisUrl: parsed.REDIS_URL,

    logLevel: parsed.LOG_LEVEL,
    serviceName: parsed.SERVICE_NAME,

    bcryptCost: parsed.BCRYPT_COST,

    sessionTtlSeconds: parsed.SESSION_TTL_SECONDS,

    seed: {
      enabled: parsed.SEED_ON_START,
      tenantKey: parsed.SEED_TENANT_KEY,
      tenantName: parsed.SEED_TENANT_NAME,
      adminEmail: parsed.SEED_ADMIN_EMAIL,
      inviteTtlHours: parsed.SEED_INVITE_TTL_HOURS,
    },
  };
}
