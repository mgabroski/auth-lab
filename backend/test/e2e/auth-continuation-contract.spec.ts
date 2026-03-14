import { randomUUID } from 'node:crypto';

import { sql } from 'kysely';
import { describe, expect, it } from 'vitest';

import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';
import { buildTestApp } from '../helpers/build-test-app';

type AcceptInviteResponse = {
  status: 'ACCEPTED';
  nextAction: 'SET_PASSWORD' | 'SIGN_IN' | 'MFA_SETUP_REQUIRED';
};

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.localhost:3000`;
}

async function createTenant(opts: { db: DbExecutor; tenantKey: string }) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: false,
      admin_invite_required: true,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
      allowed_sso: sql`ARRAY[]::text[]`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

async function createPendingInvite(opts: {
  db: DbExecutor;
  tokenHasher: { hash(input: string): string };
  tenantId: string;
  email: string;
  role: 'ADMIN' | 'MEMBER';
  tokenRaw: string;
}) {
  return opts.db
    .insertInto('invites')
    .values({
      tenant_id: opts.tenantId,
      email: opts.email.toLowerCase(),
      role: opts.role,
      status: 'PENDING',
      token_hash: opts.tokenHasher.hash(opts.tokenRaw),
      expires_at: new Date(Date.now() + 3_600_000),
      created_by_user_id: null,
    })
    .execute();
}

async function seedExistingPasswordUser(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  email: string;
  hasVerifiedMfaSecret?: boolean;
}) {
  const user = await opts.db
    .insertInto('users')
    .values({
      email: opts.email.toLowerCase(),
      name: 'Existing User',
      email_verified: true,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const passwordHash = await opts.passwordHasher.hash('Password123!');

  await opts.db
    .insertInto('auth_identities')
    .values({
      user_id: user.id,
      provider: 'password',
      password_hash: passwordHash,
      provider_subject: null,
    })
    .execute();

  if (opts.hasVerifiedMfaSecret) {
    await opts.db
      .insertInto('mfa_secrets')
      .values({
        user_id: user.id,
        encrypted_secret: 'enc:test-secret',
        issuer: 'Hubins',
        is_verified: true,
        verified_at: new Date(),
      })
      .execute();
  }

  return user;
}

describe('Continuation-flow contracts', () => {
  it('POST /auth/invites/accept returns SET_PASSWORD when the invite email has no existing user yet', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = hostForTenant(tenantKey);
    const token = `invite_${randomUUID()}`;
    const email = `fresh-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      await createPendingInvite({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        tokenRaw: token,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/invites/accept',
        headers: { host },
        payload: { token },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<AcceptInviteResponse>(res);
      expect(body).toEqual({
        status: 'ACCEPTED',
        nextAction: 'SET_PASSWORD',
      });
    } finally {
      await close();
    }
  });

  it('POST /auth/invites/accept returns SIGN_IN when the invite email already belongs to a password user', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = hostForTenant(tenantKey);
    const token = `invite_${randomUUID()}`;
    const email = `existing-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      await seedExistingPasswordUser({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        email,
      });
      await createPendingInvite({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        tokenRaw: token,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/invites/accept',
        headers: { host },
        payload: { token },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<AcceptInviteResponse>(res);
      expect(body).toEqual({
        status: 'ACCEPTED',
        nextAction: 'SIGN_IN',
      });
    } finally {
      await close();
    }
  });

  it('POST /auth/invites/accept returns MFA_SETUP_REQUIRED for an existing admin invitee without verified MFA', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = hostForTenant(tenantKey);
    const token = `invite_${randomUUID()}`;
    const email = `admin-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      await seedExistingPasswordUser({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        email,
        hasVerifiedMfaSecret: false,
      });
      await createPendingInvite({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'ADMIN',
        tokenRaw: token,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/invites/accept',
        headers: { host },
        payload: { token },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<AcceptInviteResponse>(res);
      expect(body).toEqual({
        status: 'ACCEPTED',
        nextAction: 'MFA_SETUP_REQUIRED',
      });
    } finally {
      await close();
    }
  });

  it('POST /auth/invites/accept stays on SIGN_IN for an existing admin invitee who already has verified MFA', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = hostForTenant(tenantKey);
    const token = `invite_${randomUUID()}`;
    const email = `admin-ready-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey });
      await seedExistingPasswordUser({
        db: deps.db,
        passwordHasher: deps.passwordHasher,
        email,
        hasVerifiedMfaSecret: true,
      });
      await createPendingInvite({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'ADMIN',
        tokenRaw: token,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/invites/accept',
        headers: { host },
        payload: { token },
      });

      expect(res.statusCode).toBe(200);
      const body = readJson<AcceptInviteResponse>(res);
      expect(body).toEqual({
        status: 'ACCEPTED',
        nextAction: 'SIGN_IN',
      });
    } finally {
      await close();
    }
  });
});
