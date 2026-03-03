import { buildApp } from '../../src/app/build-app';
import type { AppConfig } from '../../src/app/config';
import { createAuthCryptoHelpers } from './auth-crypto-helpers';
import { SsoProviderRegistry } from '../../src/modules/auth/sso/sso-provider-registry';
import { GoogleSsoAdapter } from '../../src/modules/auth/sso/google/google-sso.adapter';
import { MicrosoftSsoAdapter } from '../../src/modules/auth/sso/microsoft/microsoft-sso.adapter';
import { FakeSsoAdapter } from './fake-sso-adapter';
import { resetDb } from './reset-db';

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
 * - Provides safe defaults for Outbox config so tests don't require OUTBOX_* env vars.
 */
export async function buildTestApp(overrides: Partial<AppConfig> = {}) {
  // resetDb() guard requires this. Keep it local to tests.
  if (!process.env.NODE_ENV) process.env.NODE_ENV = 'test';

  const baseConfig: AppConfig = {
    nodeEnv: 'test',
    port: 0,

    databaseUrl: requireEnv('DATABASE_URL'),
    redisUrl: requireEnv('REDIS_URL'),

    logLevel: process.env.LOG_LEVEL ?? 'info',
    serviceName: process.env.SERVICE_NAME ?? 'auth-lab-backend',

    bcryptCost: 4, // always use minimum cost in tests — bcrypt cost 12 adds ~250ms per hash

    sessionTtlSeconds: 3600, // 1 hour for tests

    mfa: {
      issuer: process.env.MFA_ISSUER ?? 'Hubins',
      encryptionKeyBase64: requireEnv('MFA_ENCRYPTION_KEY_BASE64'),
      hmacKeyBase64: requireEnv('MFA_HMAC_KEY_BASE64'),
    },

    sso: {
      stateEncryptionKeyBase64:
        process.env.SSO_STATE_ENCRYPTION_KEY ?? 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      redirectBaseUrl: process.env.SSO_REDIRECT_BASE_URL ?? 'http://localhost:3000',

      googleClientId: process.env.GOOGLE_CLIENT_ID ?? 'test-google-client-id',
      googleClientSecret: process.env.GOOGLE_CLIENT_SECRET ?? 'test-google-client-secret',

      microsoftClientId: process.env.MICROSOFT_CLIENT_ID ?? 'test-microsoft-client-id',
      microsoftClientSecret: process.env.MICROSOFT_CLIENT_SECRET ?? 'test-microsoft-client-secret',
    },

    // ✅ Outbox (Step 2) — give tests safe defaults so DI never sees undefined config.outbox
    outbox: {
      pollIntervalMs: 5_000,
      batchSize: 10,
      maxAttempts: 5,
      encDefaultVersion: 'v1',
      encKeysByVersion: {
        // 32-byte key, base64-encoded (zeros) — safe for tests only
        v1: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      },
    },

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

    // ensure nested objects merge correctly
    mfa: {
      ...baseConfig.mfa,
      ...(overrides.mfa ?? {}),
    },
    sso: {
      ...baseConfig.sso,
      ...(overrides.sso ?? {}),
    },
    outbox: {
      ...baseConfig.outbox,
      ...(overrides.outbox ?? {}),
      encKeysByVersion: {
        ...baseConfig.outbox.encKeysByVersion,
        ...(overrides.outbox?.encKeysByVersion ?? {}),
      },
    },
    seed: {
      ...baseConfig.seed,
      ...(overrides.seed ?? {}),
    },
  };

  // Test doubles for provider exchange. Validation remains real.
  // Build AFTER config merge so adapter clientIds match token validation expectations.
  const googleAdapter = new FakeSsoAdapter(
    new GoogleSsoAdapter(config.sso.googleClientId, config.sso.googleClientSecret),
  );
  const microsoftAdapter = new FakeSsoAdapter(
    new MicrosoftSsoAdapter(config.sso.microsoftClientId, config.sso.microsoftClientSecret),
  );

  const testRegistry = new SsoProviderRegistry().register(googleAdapter).register(microsoftAdapter);

  const built = await buildApp(config, { ssoProviderRegistry: testRegistry });
  const cryptoHelpers = createAuthCryptoHelpers(built.deps);

  return {
    app: built.app,
    deps: built.deps,
    cryptoHelpers,
    reset: async () => resetDb(built.deps.db),
    sso: {
      googleAdapter,
      microsoftAdapter,
    },
    close: built.close,
  };
}
