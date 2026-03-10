/**
 * backend/test/e2e/auth-me.spec.ts
 *
 * WHY:
 * - Verifies GET /auth/me contract and nextAction derivation for frontend bootstrap.
 * - Covers cross-tenant session rejection and the locked nextAction precedence.
 *
 * RULES:
 * - Use buildTestApp() per test.
 * - Seed state directly via deps.db / deps.sessionStore.
 * - No beforeAll/afterAll; each test owns its own setup and close().
 */

import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import { SESSION_COOKIE_NAME } from '../../src/shared/session/session.types';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';
import type { MeResponse } from '../../src/modules/auth/auth.types';

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function extractSidCookie(headers: Record<string, unknown>): string {
  const raw = headers['set-cookie'] as string | string[] | undefined;
  const first = Array.isArray(raw) ? raw[0] : raw;

  if (typeof first !== 'string' || !first.length) {
    throw new Error('Expected set-cookie header');
  }

  return first.split(';')[0] ?? '';
}

async function createTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  isActive?: boolean;
  publicSignupEnabled?: boolean;
  memberMfaRequired?: boolean;
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: opts.isActive ?? true,
      public_signup_enabled: opts.publicSignupEnabled ?? false,
      member_mfa_required: opts.memberMfaRequired ?? false,
      allowed_email_domains: sql`'[]'::jsonb`,
    })
    .returning(['id', 'key', 'name'])
    .executeTakeFirstOrThrow();
}

async function seedUserWithPassword(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  tenantId: string;
  email: string;
  password: string;
  role: 'ADMIN' | 'MEMBER';
  name?: string;
  emailVerified?: boolean;
}) {
  const user = await opts.db
    .insertInto('users')
    .values({
      email: opts.email.toLowerCase(),
      name: opts.name ?? 'Test User',
      email_verified: opts.emailVerified ?? true,
    })
    .returning(['id', 'email', 'name'])
    .executeTakeFirstOrThrow();

  const passwordHash = await opts.passwordHasher.hash(opts.password);
  await opts.db
    .insertInto('auth_identities')
    .values({
      user_id: user.id,
      provider: 'password',
      password_hash: passwordHash,
      provider_subject: null,
    })
    .execute();

  const membership = await opts.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: opts.role,
      status: 'ACTIVE',
    })
    .returning(['id', 'role'])
    .executeTakeFirstOrThrow();

  return { user, membership };
}

describe('GET /auth/me', () => {
  it('returns 401 with no session cookie', async () => {
    const { app, close } = await buildTestApp();
    const host = `tenant-${randomUUID().slice(0, 8)}.hubins.com`;

    try {
      const res = await app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: { host },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await close();
    }
  });

  it('returns 200 with correct shape after member login', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.hubins.com`;
    const email = `member-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'MemberPass123!';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const { user, membership } = await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'MEMBER',
        name: 'Member User',
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
      });

      expect(loginRes.statusCode).toBe(200);
      const sid = extractSidCookie(loginRes.headers);

      const meRes = await app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: { host, cookie: sid },
      });

      expect(meRes.statusCode).toBe(200);
      const body = readJson<MeResponse>(meRes);

      expect(body).toEqual({
        user: {
          id: user.id,
          email: user.email,
          name: 'Member User',
        },
        membership: {
          id: membership.id,
          role: 'MEMBER',
        },
        tenant: {
          id: tenant.id,
          key: tenant.key,
          name: tenant.name,
        },
        session: {
          mfaVerified: true,
          emailVerified: true,
        },
        nextAction: 'NONE',
      });
    } finally {
      await close();
    }
  });

  it('returns nextAction NONE for MEMBER when MFA is not required', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.hubins.com`;
    const email = `member-none-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'MemberPass123!';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey, memberMfaRequired: false });
      await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'MEMBER',
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
      });
      const sid = extractSidCookie(loginRes.headers);

      const meRes = await app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: { host, cookie: sid },
      });

      expect(meRes.statusCode).toBe(200);
      expect(readJson<MeResponse>(meRes).nextAction).toBe('NONE');
    } finally {
      await close();
    }
  });

  it('returns nextAction MFA_SETUP_REQUIRED for ADMIN with no MFA secret', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.hubins.com`;
    const email = `admin-setup-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'AdminPass123!';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'ADMIN',
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
      });
      const sid = extractSidCookie(loginRes.headers);

      const meRes = await app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: { host, cookie: sid },
      });

      expect(meRes.statusCode).toBe(200);
      expect(readJson<MeResponse>(meRes).nextAction).toBe('MFA_SETUP_REQUIRED');
    } finally {
      await close();
    }
  });

  it('returns nextAction MFA_REQUIRED for ADMIN with verified MFA secret and session not yet verified', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.hubins.com`;
    const email = `admin-required-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'AdminPass123!';

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const { user } = await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'ADMIN',
      });

      const encryptedSecret = deps.encryptionService.encrypt('JBSWY3DPEHPK3PXP');
      await deps.db
        .insertInto('mfa_secrets')
        .values({
          user_id: user.id,
          encrypted_secret: encryptedSecret,
          is_verified: true,
          verified_at: new Date(),
        })
        .execute();

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
      });
      const sid = extractSidCookie(loginRes.headers);

      const meRes = await app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: { host, cookie: sid },
      });

      expect(meRes.statusCode).toBe(200);
      const body = readJson<MeResponse>(meRes);
      expect(body.session.mfaVerified).toBe(false);
      expect(body.nextAction).toBe('MFA_REQUIRED');
    } finally {
      await close();
    }
  });

  it('returns nextAction EMAIL_VERIFICATION_REQUIRED for unverified session', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = `${tenantKey}.hubins.com`;
    const email = `unverified-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      const { user, membership } = await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenant.id,
        email,
        password: 'MemberPass123!',
        role: 'MEMBER',
        emailVerified: false,
      });

      const sessionId = await deps.sessionStore.create({
        userId: user.id,
        tenantId: tenant.id,
        tenantKey,
        membershipId: membership.id,
        role: 'MEMBER',
        mfaVerified: false,
        emailVerified: false,
        createdAt: new Date().toISOString(),
      });

      const meRes = await app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: {
          host,
          cookie: `${SESSION_COOKIE_NAME}=${sessionId}`,
        },
      });

      expect(meRes.statusCode).toBe(200);
      expect(readJson<MeResponse>(meRes).nextAction).toBe('EMAIL_VERIFICATION_REQUIRED');
    } finally {
      await close();
    }
  });

  it('returns 401 when the session belongs to a different tenant', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKeyA = `tenant-a-${randomUUID().slice(0, 8)}`;
    const tenantKeyB = `tenant-b-${randomUUID().slice(0, 8)}`;
    const email = `cross-tenant-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'MemberPass123!';

    try {
      const tenantA = await createTenant({ db: deps.db, tenantKey: tenantKeyA });
      await createTenant({ db: deps.db, tenantKey: tenantKeyB });
      await seedUserWithPassword({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        tenantId: tenantA.id,
        email,
        password,
        role: 'MEMBER',
      });

      const loginRes = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host: `${tenantKeyA}.hubins.com` },
        payload: { email, password },
      });
      const sid = extractSidCookie(loginRes.headers);

      const meRes = await app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: {
          host: `${tenantKeyB}.hubins.com`,
          cookie: sid,
        },
      });

      expect(meRes.statusCode).toBe(401);
    } finally {
      await close();
    }
  });
});
