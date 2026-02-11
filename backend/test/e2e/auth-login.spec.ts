import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';

/**
 * E2E tests for POST /auth/login (Brick 7c).
 *
 * These tests set up users + identities + memberships directly
 * (skipping the register flow) to isolate login behavior.
 */

type AuthenticatedResponseBody = {
  status: 'AUTHENTICATED';
  nextAction: 'NONE' | 'MFA_SETUP_REQUIRED';
  user: { id: string; email: string; name: string };
  membership: { id: string; role: 'ADMIN' | 'MEMBER' };
};

type ErrorResponseBody = {
  error: {
    message: string;
    code?: string;
  };
};

function readJson<T>(res: { json: () => unknown }): T {
  // Fastify inject returns `any` for json() in many typings.
  // This keeps it safe and lint-clean.
  return res.json() as T;
}

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

async function seedUserWithPassword(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  tenantId: string;
  email: string;
  password: string;
  role: 'ADMIN' | 'MEMBER';
  membershipStatus?: 'ACTIVE' | 'INVITED' | 'SUSPENDED';
}) {
  const user = await opts.db
    .insertInto('users')
    .values({ email: opts.email.toLowerCase(), name: 'Test' })
    .returning(['id', 'email'])
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
      status: opts.membershipStatus ?? 'ACTIVE',
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  return { user, membership };
}

describe('POST /auth/login', () => {
  it('logs in with valid credentials → session cookie + AUTHENTICATED', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `login-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'ValidPassword123!';

    try {
      const tenant = await createTenant({ db, tenantKey });
      await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'MEMBER',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
      });

      expect(res.statusCode).toBe(200);

      const body = readJson<AuthenticatedResponseBody>(res);
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE');
      expect(body.user.email).toBe(email.toLowerCase());
      expect(body.membership.role).toBe('MEMBER');

      // Session cookie set
      const setCookie = res.headers['set-cookie'] as string;
      expect(setCookie).toBeDefined();
      expect(setCookie).toContain('sid=');
      expect(setCookie).toContain('HttpOnly');

      // Audit: login success
      const audits = await db
        .selectFrom('audit_events')
        .select(['action'])
        .where('tenant_id', '=', tenant.id)
        .where('action', '=', 'auth.login.success')
        .execute();
      expect(audits).toHaveLength(1);
    } finally {
      await close();
    }
  });

  it('admin login returns MFA_SETUP_REQUIRED', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `admin-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'AdminPass123!';

    try {
      const tenant = await createTenant({ db, tenantKey });
      await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'ADMIN',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<AuthenticatedResponseBody>(res);
      expect(body.nextAction).toBe('MFA_SETUP_REQUIRED');
    } finally {
      await close();
    }
  });

  it('rejects wrong password with generic error', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `wrongpw-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password: 'CorrectPass123!',
        role: 'MEMBER',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password: 'WrongPassword456!' },
      });

      expect(res.statusCode).toBe(401);

      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toContain('Invalid email or password');

      // Audit: login failed
      const audits = await db
        .selectFrom('audit_events')
        .select(['action'])
        .where('tenant_id', '=', tenant.id)
        .where('action', '=', 'auth.login.failed')
        .execute();
      expect(audits).toHaveLength(1);
    } finally {
      await close();
    }
  });

  it('rejects nonexistent email with generic error', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createTenant({ db, tenantKey });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email: 'nonexistent@example.com', password: 'SomePass123!' },
      });

      expect(res.statusCode).toBe(401);

      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toContain('Invalid email or password');
    } finally {
      await close();
    }
  });

  it('rejects suspended membership', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `suspended-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'ValidPass123!';

    try {
      const tenant = await createTenant({ db, tenantKey });
      await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'MEMBER',
        membershipStatus: 'SUSPENDED',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
      });

      expect(res.statusCode).toBe(403);

      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toContain('suspended');
    } finally {
      await close();
    }
  });

  it('rejects INVITED membership (invite not accepted)', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `invited-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'ValidPass123!';

    try {
      const tenant = await createTenant({ db, tenantKey });
      await seedUserWithPassword({
        db,
        passwordHasher,
        tenantId: tenant.id,
        email,
        password,
        role: 'MEMBER',
        membershipStatus: 'INVITED',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
      });

      expect(res.statusCode).toBe(409);

      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toContain('invite');
    } finally {
      await close();
    }
  });

  it('rejects user with no membership for this tenant', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, passwordHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `nomember-${randomUUID().slice(0, 8)}@example.com`;
    const password = 'ValidPass123!';

    try {
      const _tenant = await createTenant({ db, tenantKey });

      // Create user + password identity but NO membership for this tenant
      const user = await db
        .insertInto('users')
        .values({ email: email.toLowerCase(), name: 'No Member' })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const passwordHash = await passwordHasher.hash(password);
      await db
        .insertInto('auth_identities')
        .values({
          user_id: user.id,
          provider: 'password',
          password_hash: passwordHash,
          provider_subject: null,
        })
        .execute();

      const res = await app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: { host },
        payload: { email, password },
      });

      expect(res.statusCode).toBe(403);

      const body = readJson<ErrorResponseBody>(res);
      expect(body.error.message).toContain('access');
    } finally {
      await close();
    }
  });
});
