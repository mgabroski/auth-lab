import { buildApp } from '../../src/app/build-app';
import type { AppConfig } from '../../src/app/config';

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var for tests: ${name}`);
  return v;
}

/**
 * WHY:
 * - Build a Fastify app for E2E-style tests using app.inject().
 * - Keeps tests clean: build once, inject, close.
 *
 * RULES:
 * - Seed is OFF by default.
 * - Uses DATABASE_URL + REDIS_URL from your dev/test infra containers.
 */
export async function buildTestApp(overrides: Partial<AppConfig> = {}) {
  const baseConfig: AppConfig = {
    nodeEnv: 'test',
    port: 0,

    databaseUrl: requireEnv('DATABASE_URL'),
    redisUrl: requireEnv('REDIS_URL'),

    logLevel: process.env.LOG_LEVEL ?? 'info',
    serviceName: process.env.SERVICE_NAME ?? 'auth-lab-backend',

    bcryptCost: Number(process.env.BCRYPT_COST ?? 12),

    seed: {
      enabled: false, // IMPORTANT: OFF in tests by default
      tenantKey: 'goodwill-ca',
      tenantName: 'GoodWill California',
      adminEmail: 'system_admin@example.com',
      inviteTtlHours: 24 * 7,
    },
  };

  const config: AppConfig = {
    ...baseConfig,
    ...overrides,
    seed: {
      ...baseConfig.seed,
      ...(overrides.seed ?? {}),
    },
  };

  return buildApp(config);
}
