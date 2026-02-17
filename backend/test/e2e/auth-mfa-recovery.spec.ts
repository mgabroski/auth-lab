/**
 * test/e2e/auth-mfa-recovery.spec.ts
 *
 * E2E tests for POST /auth/mfa/recover (Brick 9c).
 * Covers single-use recovery code consumption.
 */

import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';
import type { LightMyRequestResponse } from 'fastify';

async function createTenant(opts: { db: DbExecutor; tenantKey: string }) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: false,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

async function seedAdminWithMfaAndRecoveryCodes(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  tenantId: string;
  email: string;
  password: string;
  mfaSecretEncrypted: string;
  recoveryCodeHashes: string[];
}): Promise<{ userId: string }> {
  const user = await opts.db
    .insertInto('users')
    .values({ email: opts.email.toLowerCase(), name: 'Admin' })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const hash = await opts.passwordHasher.hash(opts.password);

  await opts.db
    .insertInto('auth_identities')
    .values({ user_id: user.id, provider: 'password', password_hash: hash, provider_subject: null })
    .execute();

  await opts.db
    .insertInto('memberships')
    .values({ tenant_id: opts.tenantId, user_id: user.id, role: 'ADMIN', status: 'ACTIVE' })
    .execute();

  await opts.db
    .insertInto('mfa_secrets')
    .values({ user_id: user.id, encrypted_secret: opts.mfaSecretEncrypted, is_verified: true })
    .execute();

  await opts.db
    .insertInto('mfa_recovery_codes')
    .values(opts.recoveryCodeHashes.map((code_hash) => ({ user_id: user.id, code_hash })))
    .execute();

  return { userId: user.id };
}

function extractSessionCookieFromLogin(loginRes: LightMyRequestResponse): string {
  const setCookie = loginRes.headers['set-cookie'];
  const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;

  if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) {
    throw new Error('Expected set-cookie header');
  }

  return cookieHeader.split(';')[0];
}

describe('POST /auth/mfa/recover', () => {
  it('valid recovery code → 200', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';
    const recoveryCode = 'ValidCode1234567'; // 16 chars

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = deps.auth.authService.generateTotpSecretForTest();
      const encryptedSecret = deps.auth.authService.encryptSecretForTest(plainSecret);

      const codeHash = deps.auth.authService.hashRecoveryCodeForTest(recoveryCode);

      await seedAdminWithMfaAndRecoveryCodes({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
        recoveryCodeHashes: [codeHash],
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      const cookie = extractSessionCookieFromLogin(loginRes);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { recoveryCode },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json<{ status: string; nextAction: string }>();
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE');
    } finally {
      await app.close();
    }
  });

  it('same recovery code a second time → single-use (DB used_at set)', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';
    const recoveryCode = 'SingleUseCode123'; // 16 chars

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = deps.auth.authService.generateTotpSecretForTest();
      const encryptedSecret = deps.auth.authService.encryptSecretForTest(plainSecret);

      const codeHash = deps.auth.authService.hashRecoveryCodeForTest(recoveryCode);

      const { userId } = await seedAdminWithMfaAndRecoveryCodes({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
        recoveryCodeHashes: [codeHash],
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      const cookie = extractSessionCookieFromLogin(loginRes);

      // First use — succeeds
      const first = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { recoveryCode },
      });
      expect(first.statusCode).toBe(200);

      // Verify DB shows used_at set (single-use)
      const dbRow = await deps.db
        .selectFrom('mfa_recovery_codes')
        .selectAll()
        .where('user_id', '=', userId)
        .where('code_hash', '=', codeHash)
        .executeTakeFirstOrThrow();

      expect(dbRow.used_at).not.toBeNull();
    } finally {
      await app.close();
    }
  });

  it('invalid / unknown recovery code → 401', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = deps.auth.authService.generateTotpSecretForTest();
      const encryptedSecret = deps.auth.authService.encryptSecretForTest(plainSecret);

      const goodHash = deps.auth.authService.hashRecoveryCodeForTest('ValidCode1234567');

      await seedAdminWithMfaAndRecoveryCodes({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
        recoveryCodeHashes: [goodHash],
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      const cookie = extractSessionCookieFromLogin(loginRes);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { recoveryCode: 'WrongCodeXYZ12345' },
      });

      expect(res.statusCode).toBe(401);
      const body = res.json<{ error: { message: string } }>();
      expect(body.error.message).toContain('Invalid recovery code');
    } finally {
      await app.close();
    }
  });

  it('writes auth.mfa.recovery.used audit event scoped to user', async () => {
    const { app, deps } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID()}`;
    const email = `admin-${randomUUID()}@example.com`;
    const password = 'password123';
    const recoveryCode = 'AuditTestCode123'; // 16 chars

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });

      const plainSecret = deps.auth.authService.generateTotpSecretForTest();
      const encryptedSecret = deps.auth.authService.encryptSecretForTest(plainSecret);

      const codeHash = deps.auth.authService.hashRecoveryCodeForTest(recoveryCode);

      const { userId } = await seedAdminWithMfaAndRecoveryCodes({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        mfaSecretEncrypted: encryptedSecret,
        recoveryCodeHashes: [codeHash],
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKey}.hubins.com` },
        body: { email, password },
      });

      const cookie = extractSessionCookieFromLogin(loginRes);

      await app.inject({
        method: 'POST',
        url: '/auth/mfa/recover',
        headers: { host: `${tenantKey}.hubins.com`, cookie },
        body: { recoveryCode },
      });

      const auditRow = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('action', '=', 'auth.mfa.recovery.used')
        .where('user_id', '=', userId)
        .executeTakeFirst();

      expect(auditRow).toBeDefined();
    } finally {
      await app.close();
    }
  });
});
