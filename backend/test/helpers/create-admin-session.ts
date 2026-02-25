/**
 * backend/test/helpers/create-admin-session.ts
 *
 * WHY:
 * - Brick 12+ endpoints require ADMIN role + mfaVerified=true.
 * - Bootstrapping a full admin session (register, MFA setup, MFA verify) in every
 *   test would be extremely repetitive and fragile.
 * - This helper seeds the minimum DB state and drives the login + MFA verify
 *   flow via HTTP to produce a ready-to-use session cookie.
 *
 * RULES:
 * - Test-only helper — never imported in production code.
 * - Seeds user directly in DB (avoids depending on unrelated invite/register flows).
 * - Uses real crypto primitives from AppDeps (totp/encryption/hmac) — no mocking.
 * - Returns the session cookie after MFA verify (mfaVerified=true in session).
 * - Does NOT create a tenant — callers are responsible for tenant creation.
 */

import { randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { AppDeps } from '../../src/app/di';
import { expect } from 'vitest';

export type AdminSessionResult = {
  userId: string;
  cookie: string;
};

export async function createAdminSession(opts: {
  app: FastifyInstance;
  deps: AppDeps;
  tenantId: string;
  tenantKey: string;
  email: string;
  password: string;
}): Promise<AdminSessionResult> {
  const { db, passwordHasher, totpService, encryptionService, mfaKeyedHasher } = opts.deps;

  // ── 1. Create user ────────────────────────────────────────────────────────
  const user = await db
    .insertInto('users')
    .values({ email: opts.email.toLowerCase(), name: 'Admin User' })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  // ── 2. Create password identity ───────────────────────────────────────────
  const passwordHash = await passwordHasher.hash(opts.password);
  await db
    .insertInto('auth_identities')
    .values({
      user_id: user.id,
      provider: 'password',
      password_hash: passwordHash,
      provider_subject: null,
    })
    .execute();

  // ── 3. Create ADMIN membership (ACTIVE) ───────────────────────────────────
  await db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: 'ADMIN',
      status: 'ACTIVE',
    })
    .execute();

  // ── 4. Seed verified MFA secret ───────────────────────────────────────────
  // Hold onto plaintextSecret so we can generate a valid TOTP code below.
  const plaintextSecret = totpService.generateSecret();
  const encryptedSecret = encryptionService.encrypt(plaintextSecret);

  await db
    .insertInto('mfa_secrets')
    .values({
      user_id: user.id,
      encrypted_secret: encryptedSecret,
      is_verified: true,
      verified_at: new Date(),
    })
    .execute();

  // ── 5. Seed 8 recovery codes ──────────────────────────────────────────────
  const recoveryCodes = Array.from({ length: 8 }, () => randomBytes(16).toString('hex'));
  const codeHashes = recoveryCodes.map((c) => mfaKeyedHasher.hash(c));
  await db
    .insertInto('mfa_recovery_codes')
    .values(codeHashes.map((ch) => ({ user_id: user.id, code_hash: ch })))
    .execute();

  // ── 6. Login — establishes session (mfaVerified=false initially) ──────────
  const loginRes = await opts.app.inject({
    method: 'POST',
    url: '/auth/login',
    headers: { host: `${opts.tenantKey}.hubins.com` },
    body: { email: opts.email, password: opts.password },
  });
  expect(loginRes.statusCode).toBe(200);

  const loginCookieHeader = loginRes.headers['set-cookie'];
  const sessionCookie = Array.isArray(loginCookieHeader)
    ? loginCookieHeader[0]
    : (loginCookieHeader as string);
  expect(sessionCookie).toBeTruthy();

  // ── 7. Verify MFA — flips session.mfaVerified to true ────────────────────
  // Session is updated in-place; the same cookie remains valid.
  const totpCode = totpService.generateCodeForTest(plaintextSecret);
  const mfaRes = await opts.app.inject({
    method: 'POST',
    url: '/auth/mfa/verify',
    headers: { host: `${opts.tenantKey}.hubins.com`, cookie: sessionCookie },
    body: { code: totpCode },
  });
  expect(mfaRes.statusCode).toBe(200);

  return { userId: user.id, cookie: sessionCookie };
}
