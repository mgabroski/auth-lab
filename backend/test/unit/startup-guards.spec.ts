import { describe, it, expect } from 'vitest';

import {
  assertKeySeparation,
  assertLocalOidcDisabledInProduction,
  assertSsoStateKey,
} from '../../src/app/di';
import type { AppConfig } from '../../src/app/config';

/**
 * backend/test/unit/startup-guards.spec.ts
 *
 * WHY:
 * - assertKeySeparation and assertSsoStateKey are documented in .env.example
 *   as startup guards. These tests prove the guards actually throw — so the
 *   documentation claim is backed by real enforcement.
 * - Pure unit tests: no DB, no Redis, no network. Just config objects and
 *   the two guard functions.
 *
 * RULES:
 * - Never use nodeEnv='test' when testing the "should throw" cases — the
 *   guards explicitly exempt test mode. Use 'development' or 'production'.
 * - Always use nodeEnv='test' for the "should pass" cases that represent
 *   CI/test usage with placeholder keys.
 */

// ── Minimal config factory ────────────────────────────────────────────────────
// Builds the minimum AppConfig shape needed to exercise the guards.
// Does not wire any real infrastructure — guards run before any service is built.

const KEY_A = 'VjJlYds7lPHtOzCrEQNNR0O7Ukst5HzX+cnszDyXvq0='; // 32-byte base64
const KEY_B = 'pjVKt5jeXMDX5YJkbDc1dDFW4ztqO1iRyHiAHi/9TjM='; // 32-byte base64, distinct
const ALL_ZEROS = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

type MakeConfigOverrides = Omit<Partial<AppConfig>, 'sso'> & {
  mfaKey?: string;
  outboxKey?: string;
  ssoStateKey?: string;
  nodeEnv?: AppConfig['nodeEnv'];
  sso?: Partial<AppConfig['sso']>;
};

function makeConfig(overrides: MakeConfigOverrides = {}): AppConfig {
  const nodeEnv = overrides.nodeEnv ?? 'development';
  const mfaKey = overrides.mfaKey ?? KEY_A;
  const outboxKey = overrides.outboxKey ?? KEY_B;
  const ssoStateKey = overrides.ssoStateKey ?? KEY_B;

  return {
    nodeEnv,
    port: 3001,
    databaseUrl: 'postgres://localhost/test',
    redisUrl: 'redis://localhost:6379',
    logLevel: 'warn',
    serviceName: 'test',
    bcryptCost: 4,
    sessionTtlSeconds: 3600,
    mfa: {
      issuer: 'Hubins',
      encryptionKeyBase64: mfaKey,
      hmacKeyBase64: KEY_B,
    },
    sso: {
      stateEncryptionKeyBase64: ssoStateKey,
      redirectBaseUrl: 'http://localhost:3000',
      googleClientId: 'test-google-client-id',
      googleClientSecret: 'test-google-client-secret',
      microsoftClientId: 'test-microsoft-client-id',
      microsoftClientSecret: 'test-microsoft-client-secret',
      ...overrides.sso,
    },
    outbox: {
      pollIntervalMs: 5_000,
      batchSize: 10,
      maxAttempts: 5,
      encDefaultVersion: 'v1',
      encKeysByVersion: { v1: outboxKey },
    },
    email: { provider: 'noop', smtp: null },
    sentryDsn: undefined,
    seed: {
      enabled: false,
      tenantKey: 'test',
      tenantName: 'Test',
      adminEmail: 'admin@example.com',
      inviteTtlHours: 168,
    },
  };
}

// ── assertKeySeparation ───────────────────────────────────────────────────────

describe('assertKeySeparation', () => {
  it('throws when MFA key and active Outbox key are the same value in development', () => {
    const config = makeConfig({ nodeEnv: 'development', mfaKey: KEY_A, outboxKey: KEY_A });
    expect(() => assertKeySeparation(config)).toThrow(/MFA_ENCRYPTION_KEY_BASE64.*OUTBOX_ENC_KEY/i);
  });

  it('throws when MFA key and active Outbox key are the same value in production', () => {
    const config = makeConfig({ nodeEnv: 'production', mfaKey: KEY_A, outboxKey: KEY_A });
    expect(() => assertKeySeparation(config)).toThrow(/MFA_ENCRYPTION_KEY_BASE64.*OUTBOX_ENC_KEY/i);
  });

  it('does not throw when MFA key and Outbox key are distinct in development', () => {
    const config = makeConfig({ nodeEnv: 'development', mfaKey: KEY_A, outboxKey: KEY_B });
    expect(() => assertKeySeparation(config)).not.toThrow();
  });

  it('does not throw when MFA key and Outbox key are distinct in production', () => {
    const config = makeConfig({ nodeEnv: 'production', mfaKey: KEY_A, outboxKey: KEY_B });
    expect(() => assertKeySeparation(config)).not.toThrow();
  });

  it('does not throw in test mode even when keys are identical — CI uses shared placeholders', () => {
    const config = makeConfig({ nodeEnv: 'test', mfaKey: KEY_A, outboxKey: KEY_A });
    expect(() => assertKeySeparation(config)).not.toThrow();
  });

  it('does not throw in test mode when keys are the all-zeros placeholder', () => {
    const config = makeConfig({ nodeEnv: 'test', mfaKey: ALL_ZEROS, outboxKey: ALL_ZEROS });
    expect(() => assertKeySeparation(config)).not.toThrow();
  });
});

// ── assertSsoStateKey ─────────────────────────────────────────────────────────

describe('assertSsoStateKey', () => {
  it('throws when SSO state key is all-zeros in development', () => {
    const config = makeConfig({ nodeEnv: 'development', ssoStateKey: ALL_ZEROS });
    expect(() => assertSsoStateKey(config)).toThrow(/SSO_STATE_ENCRYPTION_KEY/i);
  });

  it('throws when SSO state key is all-zeros in production', () => {
    const config = makeConfig({ nodeEnv: 'production', ssoStateKey: ALL_ZEROS });
    expect(() => assertSsoStateKey(config)).toThrow(/SSO_STATE_ENCRYPTION_KEY/i);
  });

  it('does not throw when SSO state key is a real value in development', () => {
    const config = makeConfig({ nodeEnv: 'development', ssoStateKey: KEY_A });
    expect(() => assertSsoStateKey(config)).not.toThrow();
  });

  it('does not throw when SSO state key is a real value in production', () => {
    const config = makeConfig({ nodeEnv: 'production', ssoStateKey: KEY_A });
    expect(() => assertSsoStateKey(config)).not.toThrow();
  });

  it('does not throw in test mode with all-zeros key — backend E2E tests use this', () => {
    const config = makeConfig({ nodeEnv: 'test', ssoStateKey: ALL_ZEROS });
    expect(() => assertSsoStateKey(config)).not.toThrow();
  });

  it('does not throw in test mode with a real key', () => {
    const config = makeConfig({ nodeEnv: 'test', ssoStateKey: KEY_A });
    expect(() => assertSsoStateKey(config)).not.toThrow();
  });
});

// ── assertLocalOidcDisabledInProduction ───────────────────────────────────────

describe('assertLocalOidcDisabledInProduction', () => {
  it('throws when Local OIDC is enabled in production', () => {
    const config = makeConfig({
      nodeEnv: 'production',
      sso: {
        localOidc: {
          issuerUrl: 'http://localhost:4010',
          clientId: 'local-oidc-client-id',
        },
      },
    });

    expect(() => assertLocalOidcDisabledInProduction(config)).toThrow(/LOCAL_OIDC_ENABLED/i);
  });

  it('does not throw when Local OIDC is enabled in development', () => {
    const config = makeConfig({
      nodeEnv: 'development',
      sso: {
        localOidc: {
          issuerUrl: 'http://localhost:4010',
          clientId: 'local-oidc-client-id',
        },
      },
    });

    expect(() => assertLocalOidcDisabledInProduction(config)).not.toThrow();
  });

  it('does not throw when Local OIDC is enabled in test', () => {
    const config = makeConfig({
      nodeEnv: 'test',
      sso: {
        localOidc: {
          issuerUrl: 'http://localhost:4010',
          clientId: 'local-oidc-client-id',
        },
      },
    });

    expect(() => assertLocalOidcDisabledInProduction(config)).not.toThrow();
  });

  it('does not throw in production when Local OIDC is disabled', () => {
    const config = makeConfig({ nodeEnv: 'production' });
    expect(() => assertLocalOidcDisabledInProduction(config)).not.toThrow();
  });
});
