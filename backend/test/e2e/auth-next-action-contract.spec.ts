import { randomUUID } from 'node:crypto';

import { sql } from 'kysely';
import { describe, expect, it } from 'vitest';

import type { AuthNextAction, AuthResult, MeResponse } from '../../src/modules/auth/auth.types';
import type { DbExecutor } from '../../src/shared/db/db';
import type { PasswordHasher } from '../../src/shared/security/password-hasher';
import { getSessionCookieName } from '../../src/shared/session/session.types';
import { buildTestApp } from '../helpers/build-test-app';

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.localhost:3000`;
}

function extractSidCookie(headers: Record<string, unknown>): string {
  const raw = headers['set-cookie'] as string | string[] | undefined;
  const first = Array.isArray(raw) ? raw[0] : raw;

  if (typeof first !== 'string' || !first.length) {
    throw new Error('Expected set-cookie header');
  }

  const cookie = first.split(';')[0];
  const sessionCookieName = getSessionCookieName(false);

  if (!cookie?.startsWith(`${sessionCookieName}=`)) {
    throw new Error(`Expected ${sessionCookieName} cookie, got: ${first}`);
  }

  return cookie;
}

async function createTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  publicSignupEnabled?: boolean;
  memberMfaRequired?: boolean;
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: opts.publicSignupEnabled ?? false,
      admin_invite_required: false,
      member_mfa_required: opts.memberMfaRequired ?? false,
      allowed_email_domains: sql`'[]'::jsonb`,
      allowed_sso: sql`ARRAY[]::text[]`,
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
  emailVerified?: boolean;
  hasVerifiedMfaSecret?: boolean;
  name?: string;
}) {
  const user = await opts.db
    .insertInto('users')
    .values({
      email: opts.email.toLowerCase(),
      name: opts.name ?? 'Contract User',
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

  return { user, membership };
}

async function createAcceptedInvite(opts: {
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
      status: 'ACCEPTED',
      token_hash: opts.tokenHasher.hash(opts.tokenRaw),
      expires_at: new Date(Date.now() + 3_600_000),
      used_at: new Date(),
      created_by_user_id: null,
    })
    .execute();
}

type LoginScenario = {
  name: string;
  role: 'ADMIN' | 'MEMBER';
  memberMfaRequired: boolean;
  emailVerified: boolean;
  hasVerifiedMfaSecret: boolean;
  expectedNextAction: AuthNextAction;
};

const LOGIN_MATRIX: LoginScenario[] = [
  {
    name: 'member with no tenant MFA requirement resolves to NONE',
    role: 'MEMBER',
    memberMfaRequired: false,
    emailVerified: true,
    hasVerifiedMfaSecret: false,
    expectedNextAction: 'NONE',
  },
  {
    name: 'member with tenant MFA requirement and no verified secret resolves to MFA_SETUP_REQUIRED',
    role: 'MEMBER',
    memberMfaRequired: true,
    emailVerified: true,
    hasVerifiedMfaSecret: false,
    expectedNextAction: 'MFA_SETUP_REQUIRED',
  },
  {
    name: 'member with tenant MFA requirement and a verified secret resolves to MFA_REQUIRED',
    role: 'MEMBER',
    memberMfaRequired: true,
    emailVerified: true,
    hasVerifiedMfaSecret: true,
    expectedNextAction: 'MFA_REQUIRED',
  },
  {
    name: 'admin without a verified secret resolves to MFA_SETUP_REQUIRED',
    role: 'ADMIN',
    memberMfaRequired: false,
    emailVerified: true,
    hasVerifiedMfaSecret: false,
    expectedNextAction: 'MFA_SETUP_REQUIRED',
  },
  {
    name: 'admin with a verified secret resolves to MFA_REQUIRED',
    role: 'ADMIN',
    memberMfaRequired: false,
    emailVerified: true,
    hasVerifiedMfaSecret: true,
    expectedNextAction: 'MFA_REQUIRED',
  },
  {
    name: 'email verification takes precedence over MFA requirements',
    role: 'ADMIN',
    memberMfaRequired: true,
    emailVerified: false,
    hasVerifiedMfaSecret: true,
    expectedNextAction: 'EMAIL_VERIFICATION_REQUIRED',
  },
];

describe('NextAction contract matrix', () => {
  for (const scenario of LOGIN_MATRIX) {
    it(`POST /auth/login + GET /auth/me — ${scenario.name}`, async () => {
      const { app, deps, close } = await buildTestApp();
      const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
      const host = hostForTenant(tenantKey);
      const email = `${scenario.role.toLowerCase()}-${randomUUID().slice(0, 8)}@example.com`;
      const password = 'Password123!';

      try {
        const tenant = await createTenant({
          db: deps.db,
          tenantKey,
          memberMfaRequired: scenario.memberMfaRequired,
        });

        const { user, membership } = await seedUserWithPassword({
          db: deps.db,
          passwordHasher: deps.passwordHasher,
          tenantId: tenant.id,
          email,
          password,
          role: scenario.role,
          emailVerified: scenario.emailVerified,
          hasVerifiedMfaSecret: scenario.hasVerifiedMfaSecret,
        });

        const loginRes = await app.inject({
          method: 'POST',
          url: '/auth/login',
          headers: { host },
          payload: { email, password },
        });

        expect(loginRes.statusCode).toBe(200);
        const loginBody = readJson<AuthResult>(loginRes);
        expect(loginBody.status).toBe(
          scenario.expectedNextAction === 'EMAIL_VERIFICATION_REQUIRED'
            ? 'EMAIL_VERIFICATION_REQUIRED'
            : 'AUTHENTICATED',
        );
        expect(loginBody.nextAction).toBe(scenario.expectedNextAction);
        expect(loginBody.user.id).toBe(user.id);
        expect(loginBody.membership.id).toBe(membership.id);

        const sidCookie = extractSidCookie(loginRes.headers);
        const meRes = await app.inject({
          method: 'GET',
          url: '/auth/me',
          headers: { host, cookie: sidCookie },
        });

        expect(meRes.statusCode).toBe(200);
        const meBody = readJson<MeResponse>(meRes);
        expect(meBody.nextAction).toBe(scenario.expectedNextAction);
        expect(meBody.user.id).toBe(user.id);
        expect(meBody.membership.id).toBe(membership.id);
        expect(meBody.session.emailVerified).toBe(scenario.emailVerified);
      } finally {
        await close();
      }
    });
  }

  it('POST /auth/signup returns EMAIL_VERIFICATION_REQUIRED for a new public-signup session and /auth/me agrees', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = hostForTenant(tenantKey);
    const email = `signup-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createTenant({
        db: deps.db,
        tenantKey,
        publicSignupEnabled: true,
        memberMfaRequired: false,
      });

      const signupRes = await app.inject({
        method: 'POST',
        url: '/auth/signup',
        headers: { host },
        payload: {
          email,
          password: 'Password123!',
          name: 'Signup User',
        },
      });

      expect(signupRes.statusCode).toBe(201);
      const signupBody = readJson<AuthResult>(signupRes);
      expect(signupBody.status).toBe('EMAIL_VERIFICATION_REQUIRED');
      expect(signupBody.nextAction).toBe('EMAIL_VERIFICATION_REQUIRED');

      const sidCookie = extractSidCookie(signupRes.headers);
      const meRes = await app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: { host, cookie: sidCookie },
      });

      expect(meRes.statusCode).toBe(200);
      const meBody = readJson<MeResponse>(meRes);
      expect(meBody.nextAction).toBe('EMAIL_VERIFICATION_REQUIRED');
      expect(meBody.session.emailVerified).toBe(false);
    } finally {
      await close();
    }
  });

  it('POST /auth/register resolves MEMBER invite registration to NONE', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = hostForTenant(tenantKey);
    const email = `member-register-${randomUUID().slice(0, 8)}@example.com`;
    const inviteToken = `invite_${randomUUID()}`;

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey, memberMfaRequired: false });
      await createAcceptedInvite({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        tokenRaw: inviteToken,
      });

      const registerRes = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host },
        payload: {
          email,
          password: 'Password123!',
          name: 'Member Register',
          inviteToken,
        },
      });

      expect(registerRes.statusCode).toBe(201);
      const body = readJson<AuthResult>(registerRes);
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('NONE');
    } finally {
      await close();
    }
  });

  it('POST /auth/register resolves ADMIN invite registration to MFA_SETUP_REQUIRED', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;
    const host = hostForTenant(tenantKey);
    const email = `admin-register-${randomUUID().slice(0, 8)}@example.com`;
    const inviteToken = `invite_${randomUUID()}`;

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey, memberMfaRequired: false });
      await createAcceptedInvite({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'ADMIN',
        tokenRaw: inviteToken,
      });

      const registerRes = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host },
        payload: {
          email,
          password: 'Password123!',
          name: 'Admin Register',
          inviteToken,
        },
      });

      expect(registerRes.statusCode).toBe(201);
      const body = readJson<AuthResult>(registerRes);
      expect(body.status).toBe('AUTHENTICATED');
      expect(body.nextAction).toBe('MFA_SETUP_REQUIRED');
    } finally {
      await close();
    }
  });
});
