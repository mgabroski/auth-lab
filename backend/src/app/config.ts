/**
 * backend/src/app/config.ts
 *
 * WHY:
 * - Central env parsing + validation.
 * - Adds email delivery config (EMAIL_PROVIDER + SMTP_*).
 * - Adds Outbox config for durable email delivery.
 * - Base64 key fields now validate decoded byte length at parse time (fail-fast).
 *
 * RULES:
 * - Outbox worker must not run in test (enforced in build-app).
 * - OUTBOX_ENC_KEY_V1 required; defaultVersion must reference an available key.
 * - In production, EMAIL_PROVIDER must be 'smtp' — noop is dev/test only.
 *   This is enforced at DI wiring time in di.ts (not here), so the config
 *   itself stays composable with test overrides.
 *
 * X10 UPDATE:
 * - Added optional SENTRY_DSN. When absent (dev, CI, test), Sentry is never
 *   initialised and captureException() is a safe no-op.
 *
 * 9/10 HARDENING:
 * - Base64KeySchema32: validates that the decoded value is exactly 32 bytes.
 *   AES-256-GCM requires a 256-bit (32-byte) key. A misconfigured 16-byte key
 *   previously threw deep inside EncryptionService constructor during DI
 *   assembly. It now fails at config parse time with a clear error.
 * - Added email provider config: EMAIL_PROVIDER ('noop' | 'smtp') and SMTP_*
 *   fields for SMTP transport.
 */

import 'dotenv/config';
import { z } from 'zod';

const NodeEnvSchema = z.enum(['development', 'test', 'production']).default('development');

// Base64 string with no byte-length constraint — used for HMAC keys and
// other non-AES fields where the length varies.
const Base64Schema = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9+/=]+$/, 'Must be base64');

// Base64 string that must decode to exactly 32 bytes (AES-256 key requirement).
// Generate with: openssl rand -base64 32
const Base64KeySchema32 = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9+/=]+$/, 'Must be base64')
  .refine(
    (v) => Buffer.from(v, 'base64').length === 32,
    'Must decode to exactly 32 bytes. Generate with: openssl rand -base64 32',
  );

const OutboxEncVersionSchema = z
  .string()
  .regex(/^v[0-9]+$/, 'Must be like v1, v2')
  .default('v1');

const emptyStringToUndefined = (value: unknown): unknown => {
  if (typeof value === 'string' && value.trim() === '') return undefined;
  return value;
};

const EnvBooleanSchema = z.preprocess((value) => {
  const nonEmptyValue = emptyStringToUndefined(value);
  if (typeof nonEmptyValue !== 'string') return nonEmptyValue;

  const normalized = nonEmptyValue.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1') return true;
  if (normalized === 'false' || normalized === '0') return false;

  return nonEmptyValue;
}, z.boolean().optional());

const CpAuthModeSchema = z.preprocess(
  emptyStringToUndefined,
  z.enum(['none', 'session']).optional(),
);

const ConfigSchema = z.object({
  NODE_ENV: NodeEnvSchema,
  PORT: z.coerce.number().default(3000),

  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),

  // Logging / service identity
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly']).default('info'),
  SERVICE_NAME: z.string().default('auth-lab-backend'),

  BCRYPT_COST: z.coerce.number().int().min(4).max(15).default(12),

  // Session
  SESSION_TTL_SECONDS: z.coerce.number().int().min(300).max(604800).default(86400),

  // MFA (Brick 9)
  MFA_ISSUER: z.string().min(1).default('Hubins'),
  // AES-256-GCM key — must be exactly 32 bytes when base64-decoded
  MFA_ENCRYPTION_KEY_BASE64: Base64KeySchema32,
  // HMAC-SHA256 key — variable length acceptable; 32 bytes recommended
  MFA_HMAC_KEY_BASE64: Base64Schema,

  // SSO (Brick 10)
  // AES-256-GCM key — must be exactly 32 bytes when base64-decoded
  SSO_STATE_ENCRYPTION_KEY: Base64KeySchema32,
  SSO_REDIRECT_BASE_URL: z.string().url(),
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  MICROSOFT_CLIENT_ID: z.string().min(1),
  MICROSOFT_CLIENT_SECRET: z.string().min(1),

  // Local OIDC server — CI only (Phase 6/7 SSO proof gap closure)
  // When LOCAL_OIDC_ENABLED=true, di.ts registers LocalOidcSsoAdapter for both
  // 'google' and 'microsoft' SSO provider slots instead of the real adapters.
  // The local OIDC server (infra/oidc-server/) issues real RS256 JWTs so the
  // full cryptographic validation path is proven in CI without real credentials.
  // NEVER set LOCAL_OIDC_ENABLED=true in staging or production.
  LOCAL_OIDC_ENABLED: z.coerce.boolean().default(false),
  LOCAL_OIDC_ISSUER: z.string().url().optional(),
  LOCAL_OIDC_CLIENT_ID: z.string().optional(),

  // Outbox (PR2)
  OUTBOX_POLL_INTERVAL_MS: z.coerce.number().int().min(250).max(60_000).default(5_000),
  OUTBOX_BATCH_SIZE: z.coerce.number().int().min(1).max(100).default(10),
  OUTBOX_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(20).default(5),

  OUTBOX_ENC_DEFAULT_VERSION: OutboxEncVersionSchema,
  // AES-256-GCM key — must be exactly 32 bytes when base64-decoded
  OUTBOX_ENC_KEY_V1: Base64KeySchema32,
  OUTBOX_ENC_KEY_V2: Base64KeySchema32.optional(),
  OUTBOX_ENC_KEY_V3: Base64KeySchema32.optional(),

  // Email delivery
  // 'noop'  — logs only, never sends (dev/test default)
  // 'smtp'  — real SMTP delivery (required in production)
  EMAIL_PROVIDER: z.enum(['noop', 'smtp']).default('noop'),

  // SMTP config — required when EMAIL_PROVIDER=smtp
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(587),
  // true = TLS from connection start (port 465); false = STARTTLS (port 587)
  SMTP_SECURE: z
    .string()
    .transform((v) => v === 'true')
    .default('false'),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().default('Hubins <noreply@hubins.com>'),
  // Public base URL template for token links in emails.
  // Use '{tenantKey}' as a placeholder: 'https://{tenantKey}.hubins.com'
  SMTP_PUBLIC_BASE_URL: z.string().default('https://{tenantKey}.hubins.com'),

  // X10 — Sentry (optional; omitting disables Sentry entirely)
  SENTRY_DSN: z.string().url().optional(),

  // Control Plane exposure/auth mode
  // CP_ENABLED controls whether the backend CP route surface is registered.
  // CP_AUTH_MODE controls the auth policy applied to those routes.
  // CP_NO_AUTH_ALLOWED is a deprecated compatibility alias for CP_AUTH_MODE=none.
  CP_ENABLED: EnvBooleanSchema,
  CP_AUTH_MODE: CpAuthModeSchema,
  CP_NO_AUTH_ALLOWED: EnvBooleanSchema,

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

export type SmtpConfig = {
  host: string;
  port: number;
  secure: boolean;
  auth?: { user: string; pass: string };
  from: string;
  publicBaseUrl: string;
};

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
    /**
     * CI-only: when set, LocalOidcSsoAdapter is used for all SSO providers
     * instead of real Google/Microsoft adapters. Never set in production.
     */
    localOidc?: {
      issuerUrl: string;
      clientId: string;
    };
  };

  outbox: {
    pollIntervalMs: number;
    batchSize: number;
    maxAttempts: number;
    encDefaultVersion: string;
    encKeysByVersion: Record<string, string>;
  };

  email: {
    provider: 'noop' | 'smtp';
    smtp: SmtpConfig | null;
  };

  /** X10: undefined when SENTRY_DSN is not set — Sentry stays uninitialised. */
  sentryDsn: string | undefined;

  controlPlane: {
    enabled: boolean;
    authMode: 'none' | 'session';
    noAuthAllowed: boolean;
  };

  seed: {
    enabled: boolean;
    tenantKey: string;
    tenantName: string;
    adminEmail: string;
    inviteTtlHours: number;
  };
};

function buildSmtpConfig(parsed: z.infer<typeof ConfigSchema>): SmtpConfig | null {
  if (parsed.EMAIL_PROVIDER !== 'smtp') return null;

  if (!parsed.SMTP_HOST) {
    throw new Error('Config: EMAIL_PROVIDER=smtp requires SMTP_HOST to be set');
  }
  if (!parsed.SMTP_FROM) {
    throw new Error('Config: EMAIL_PROVIDER=smtp requires SMTP_FROM to be set');
  }

  const auth =
    parsed.SMTP_USER && parsed.SMTP_PASS
      ? { user: parsed.SMTP_USER, pass: parsed.SMTP_PASS }
      : undefined;

  return {
    host: parsed.SMTP_HOST,
    port: parsed.SMTP_PORT,
    secure: parsed.SMTP_SECURE,
    auth,
    from: parsed.SMTP_FROM,
    publicBaseUrl: parsed.SMTP_PUBLIC_BASE_URL,
  };
}

export function buildConfig(): AppConfig {
  const parsed = ConfigSchema.parse(process.env);

  const legacyNoAuthAllowed = parsed.CP_NO_AUTH_ALLOWED === true;
  const controlPlaneEnabled = parsed.CP_ENABLED ?? legacyNoAuthAllowed;
  const controlPlaneAuthMode = parsed.CP_AUTH_MODE ?? (legacyNoAuthAllowed ? 'none' : 'session');

  if (parsed.NODE_ENV === 'production' && controlPlaneEnabled && controlPlaneAuthMode === 'none') {
    throw new Error(
      'Config: CP_AUTH_MODE=none is forbidden in production. Configure real CP auth before enabling Control Plane routes.',
    );
  }

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
      // CI-only local OIDC override (see LOCAL_OIDC_ENABLED comment in schema)
      ...(parsed.LOCAL_OIDC_ENABLED && parsed.LOCAL_OIDC_ISSUER && parsed.LOCAL_OIDC_CLIENT_ID
        ? {
            localOidc: {
              issuerUrl: parsed.LOCAL_OIDC_ISSUER,
              clientId: parsed.LOCAL_OIDC_CLIENT_ID,
            },
          }
        : {}),
    },

    outbox: {
      pollIntervalMs: parsed.OUTBOX_POLL_INTERVAL_MS,
      batchSize: parsed.OUTBOX_BATCH_SIZE,
      maxAttempts: parsed.OUTBOX_MAX_ATTEMPTS,
      encDefaultVersion: parsed.OUTBOX_ENC_DEFAULT_VERSION,
      encKeysByVersion,
    },

    email: {
      provider: parsed.EMAIL_PROVIDER,
      smtp: buildSmtpConfig(parsed),
    },

    sentryDsn: parsed.SENTRY_DSN,

    controlPlane: {
      enabled: controlPlaneEnabled,
      authMode: controlPlaneAuthMode,
      noAuthAllowed: controlPlaneAuthMode === 'none',
    },

    seed: {
      enabled: parsed.SEED_ON_START,
      tenantKey: parsed.SEED_TENANT_KEY,
      tenantName: parsed.SEED_TENANT_NAME,
      adminEmail: parsed.SEED_ADMIN_EMAIL,
      inviteTtlHours: parsed.SEED_INVITE_TTL_HOURS,
    },
  };
}
