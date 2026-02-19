import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { TokenHasher } from '../../src/shared/security/token-hasher';

/**
 *
 *
 * Flow: admin creates invite → user accepts invite → user registers.
 * These tests set up ACCEPTED invites directly.
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

async function createAcceptedInvite(opts: {
  db: DbExecutor;
  tokenHasher: TokenHasher;
  tenantId: string;
  email: string;
  role: 'ADMIN' | 'MEMBER';
  tokenRaw: string;
}) {
  const tokenHash = opts.tokenHasher.hash(opts.tokenRaw);
  return opts.db
    .insertInto('invites')
    .values({
      tenant_id: opts.tenantId,
      email: opts.email.toLowerCase(),
      role: opts.role,
      status: 'ACCEPTED',
      token_hash: tokenHash,
      expires_at: new Date(Date.now() + 3600_000),
      used_at: new Date(),
      created_by_user_id: null,
    })
    .returning(['id', 'tenant_id', 'token_hash'])
    .executeTakeFirstOrThrow();
}

describe('POST /auth/register', () => {
  it('registers a new user from an accepted invite → creates user + identity + membership + session cookie', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, tokenHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `user-${randomUUID().slice(0, 8)}@example.com`;
    const tokenRaw = `inv_${randomUUID()}_${randomUUID()}`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      await createAcceptedInvite({
        db,
        tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        tokenRaw,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host },
        payload: {
          email,
          password: 'SecurePass123!',
          name: 'Test User',
          inviteToken: tokenRaw,
        },
      });

      expect(res.statusCode).toBe(201);

      const body = readJson<AuthenticatedResponseBody>(res);
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE'); // MEMBER, no MFA required
      expect(body.user.email).toBe(email.toLowerCase());
      expect(body.user.name).toBe('Test User');
      expect(body.membership.role).toBe('MEMBER');

      // Session cookie set
      const setCookie = res.headers['set-cookie'] as string;
      expect(setCookie).toBeDefined();
      expect(setCookie).toContain('sid=');
      expect(setCookie).toContain('HttpOnly');

      // User created in DB
      const users = await db
        .selectFrom('users')
        .selectAll()
        .where('email', '=', email.toLowerCase())
        .execute();
      expect(users).toHaveLength(1);

      // Auth identity created
      const identities = await db
        .selectFrom('auth_identities')
        .selectAll()
        .where('user_id', '=', users[0].id)
        .where('provider', '=', 'password')
        .execute();
      expect(identities).toHaveLength(1);

      // Membership created and ACTIVE
      const memberships = await db
        .selectFrom('memberships')
        .selectAll()
        .where('tenant_id', '=', tenant.id)
        .where('user_id', '=', users[0].id)
        .execute();
      expect(memberships).toHaveLength(1);
      expect(memberships[0].status).toBe('ACTIVE');
      expect(memberships[0].role).toBe('MEMBER');

      // Audit events written
      const audits = await db
        .selectFrom('audit_events')
        .selectAll()
        .where('tenant_id', '=', tenant.id)
        .execute();
      const actions = audits.map((a) => a.action);
      expect(actions).toContain('auth.register.success');
      expect(actions).toContain('user.created');

      // PII hardening: success audits must not include raw email
      const relevant = audits.filter(
        (a) => a.action === 'auth.register.success' || a.action === 'user.created',
      );
      expect(relevant.length).toBeGreaterThan(0);
      for (const a of relevant) {
        const meta = a.metadata as Record<string, unknown>;
        expect(meta.email).toBeUndefined();
      }
    } finally {
      await close();
    }
  });

  it('admin registration returns MFA_SETUP_REQUIRED', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, tokenHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `admin-${randomUUID().slice(0, 8)}@example.com`;
    const tokenRaw = `inv_${randomUUID()}_${randomUUID()}`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      await createAcceptedInvite({
        db,
        tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'ADMIN',
        tokenRaw,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host },
        payload: { email, password: 'SecurePass123!', name: 'Admin User', inviteToken: tokenRaw },
      });

      expect(res.statusCode).toBe(201);

      const body = readJson<AuthenticatedResponseBody>(res);
      expect(body.nextAction).toBe('MFA_SETUP_REQUIRED');
      expect(body.membership.role).toBe('ADMIN');
    } finally {
      await close();
    }
  });

  it('rejects duplicate registration (already registered)', async () => {
    const { app, deps, close } = await buildTestApp();
    const { db, tokenHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `dup-${randomUUID().slice(0, 8)}@example.com`;
    const tokenRaw = `inv_${randomUUID()}_${randomUUID()}`;

    try {
      const tenant = await createTenant({ db, tenantKey });
      await createAcceptedInvite({
        db,
        tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        tokenRaw,
      });

      // First registration succeeds
      const res1 = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host },
        payload: { email, password: 'SecurePass123!', name: 'User', inviteToken: tokenRaw },
      });
      expect(res1.statusCode).toBe(201);

      // Second registration fails (auth identity already exists)
      const res2 = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host },
        payload: { email, password: 'SecurePass123!', name: 'User', inviteToken: tokenRaw },
      });
      expect(res2.statusCode).toBe(409);

      const body = readJson<ErrorResponseBody>(res2);
      expect(body.error.message).toContain('already registered');
    } finally {
      await close();
    }
  });
});
