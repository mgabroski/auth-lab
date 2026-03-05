/**
 * backend/src/app/config.ts
 *
 * WHY:
 * - Central env parsing + validation.
 * - Adds Outbox config for durable email delivery.
 *
 * RULES:
 * - Outbox worker must not run in test (enforced in build-app).
 * - OUTBOX_ENC_KEY_V1 required; defaultVersion must reference an available key.
 *
 * X10 UPDATE:
 * - Added optional SENTRY_DSN. When absent (dev, CI, test), Sentry is never
 *   initialised and captureException() is a safe no-op.
 */

import 'dotenv/config';
import { z } from 'zod';

const NodeEnvSchema = z.enum(['development', 'test', 'production']).default('development');

const Base64Schema = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9+/=]+$/, 'Must be base64');

const OutboxEncVersionSchema = z
  .string()
  .regex(/^v[0-9]+$/, 'Must be like v1, v2')
  .default('v1');

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

  // MFA (Brick 9)
  MFA_ISSUER: z.string().min(1).default('Hubins'),
  MFA_ENCRYPTION_KEY_BASE64: Base64Schema,
  MFA_HMAC_KEY_BASE64: Base64Schema,

  // SSO (Brick 10)
  SSO_STATE_ENCRYPTION_KEY: Base64Schema,
  SSO_REDIRECT_BASE_URL: z.string().url(),
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  MICROSOFT_CLIENT_ID: z.string().min(1),
  MICROSOFT_CLIENT_SECRET: z.string().min(1),

  // Outbox (PR2)
  OUTBOX_POLL_INTERVAL_MS: z.coerce.number().int().min(250).max(60_000).default(5_000),
  OUTBOX_BATCH_SIZE: z.coerce.number().int().min(1).max(100).default(10),
  OUTBOX_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(20).default(5),

  OUTBOX_ENC_DEFAULT_VERSION: OutboxEncVersionSchema,
  OUTBOX_ENC_KEY_V1: Base64Schema,
  OUTBOX_ENC_KEY_V2: Base64Schema.optional(),
  OUTBOX_ENC_KEY_V3: Base64Schema.optional(),

  // X10 — Sentry (optional; omitting disables Sentry entirely)
  SENTRY_DSN: z.string().url().optional(),

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

  mfa: {
    issuer: string;
    encryptionKeyBase64: string;
    hmacKeyBase64: string;
  };

  sso: {
    stateEncryptionKeyBase64: string;
    redirectBaseUrl: string;
    googleClientId: string;
    googleClientSecret: string;
    microsoftClientId: string;
    microsoftClientSecret: string;
  };

  outbox: {
    pollIntervalMs: number;
    batchSize: number;
    maxAttempts: number;
    encDefaultVersion: string;
    encKeysByVersion: Record<string, string>;
  };

  /** X10: undefined when SENTRY_DSN is not set — Sentry stays uninitialised. */
  sentryDsn: string | undefined;

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

  const encKeysByVersion: Record<string, string> = {
    v1: parsed.OUTBOX_ENC_KEY_V1,
  };
  if (parsed.OUTBOX_ENC_KEY_V2) encKeysByVersion.v2 = parsed.OUTBOX_ENC_KEY_V2;
  if (parsed.OUTBOX_ENC_KEY_V3) encKeysByVersion.v3 = parsed.OUTBOX_ENC_KEY_V3;

  if (!encKeysByVersion[parsed.OUTBOX_ENC_DEFAULT_VERSION]) {
    throw new Error(
      `Config: OUTBOX_ENC_DEFAULT_VERSION=${parsed.OUTBOX_ENC_DEFAULT_VERSION} has no configured key`,
    );
  }

  return {
    nodeEnv: parsed.NODE_ENV,
    port: parsed.PORT,
    databaseUrl: parsed.DATABASE_URL,
    redisUrl: parsed.REDIS_URL,

    logLevel: parsed.LOG_LEVEL,
    serviceName: parsed.SERVICE_NAME,

    bcryptCost: parsed.BCRYPT_COST,

    sessionTtlSeconds: parsed.SESSION_TTL_SECONDS,

    mfa: {
      issuer: parsed.MFA_ISSUER,
      encryptionKeyBase64: parsed.MFA_ENCRYPTION_KEY_BASE64,
      hmacKeyBase64: parsed.MFA_HMAC_KEY_BASE64,
    },

    sso: {
      stateEncryptionKeyBase64: parsed.SSO_STATE_ENCRYPTION_KEY,
      redirectBaseUrl: parsed.SSO_REDIRECT_BASE_URL,
      googleClientId: parsed.GOOGLE_CLIENT_ID,
      googleClientSecret: parsed.GOOGLE_CLIENT_SECRET,
      microsoftClientId: parsed.MICROSOFT_CLIENT_ID,
      microsoftClientSecret: parsed.MICROSOFT_CLIENT_SECRET,
    },

    outbox: {
      pollIntervalMs: parsed.OUTBOX_POLL_INTERVAL_MS,
      batchSize: parsed.OUTBOX_BATCH_SIZE,
      maxAttempts: parsed.OUTBOX_MAX_ATTEMPTS,
      encDefaultVersion: parsed.OUTBOX_ENC_DEFAULT_VERSION,
      encKeysByVersion,
    },

    sentryDsn: parsed.SENTRY_DSN,

    seed: {
      enabled: parsed.SEED_ON_START,
      tenantKey: parsed.SEED_TENANT_KEY,
      tenantName: parsed.SEED_TENANT_NAME,
      adminEmail: parsed.SEED_ADMIN_EMAIL,
      inviteTtlHours: parsed.SEED_INVITE_TTL_HOURS,
    },
  };
}
