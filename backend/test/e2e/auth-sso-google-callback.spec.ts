import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';

import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import {
  buildFakeIdToken,
  createInvite,
  createSsoTenant,
  createUserWithMembership,
  getSsoStateFromStart,
} from '../helpers/sso-test-fixtures';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID ?? 'test-google-client-id';

function getSetCookieHeaders(setCookieHeader: string | string[] | undefined): string[] {
  if (Array.isArray(setCookieHeader)) return setCookieHeader;
  return setCookieHeader ? [setCookieHeader] : [];
}

function extractSessionIdFromSetCookie(setCookieHeader: string | string[] | undefined): string {
  const sessionCookie = getSetCookieHeaders(setCookieHeader).find((cookie) =>
    cookie.startsWith('sid='),
  );

  if (!sessionCookie) {
    throw new Error('Expected Set-Cookie header to contain a session cookie');
  }

  const match = /^sid=([^;]+)/.exec(sessionCookie);
  if (!match) {
    throw new Error(`Could not extract sid cookie from: ${sessionCookie}`);
  }

  return match[1];
}

function expectSsoCallbackCookies(setCookieHeader: string | string[] | undefined): void {
  const cookies = getSetCookieHeaders(setCookieHeader);

  expect(cookies.some((cookie) => cookie.startsWith('sid='))).toBe(true);
  expect(
    cookies.some(
      (cookie) =>
        cookie.startsWith('sso-state=;') &&
        cookie.includes('Max-Age=0') &&
        cookie.includes('SameSite=Lax'),
    ),
  ).toBe(true);
}

async function createAgentGroup(opts: {
  db: DbExecutor;
  tenantId: string;
  status?: 'ACTIVE' | 'ARCHIVED';
}): Promise<{ id: string }> {
  const name = `Agent Group ${randomUUID().slice(0, 8)}`;
  const status = opts.status ?? 'ACTIVE';

  return opts.db
    .insertInto('tenant_groups')
    .values({
      tenant_id: opts.tenantId,
      name,
      normalized_name: name.toLowerCase(),
      description: null,
      level: 'AGENT',
      status,
      created_by_membership_id: null,
      updated_by_membership_id: null,
      archived_at: status === 'ARCHIVED' ? new Date() : null,
      archived_by_membership_id: null,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();
}

async function attachInviteAgentGroup(opts: {
  db: DbExecutor;
  tenantId: string;
  inviteId: string;
  groupId: string;
}): Promise<void> {
  await opts.db
    .insertInto('invite_agent_groups')
    .values({
      tenant_id: opts.tenantId,
      invite_id: opts.inviteId,
      group_id: opts.groupId,
    })
    .execute();
}

describe('GET /auth/sso/google/callback', () => {
  it('success: ACTIVE member → 302 done?nextAction=NONE + sets session cookie + audit written', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const email = `u-${randomUUID().slice(0, 8)}@example.com`;

      const created = await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'USER',
        status: 'ACTIVE',
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(302);
      expect(String(res.headers.location)).toContain('/auth/sso/done?nextAction=NONE');
      expectSsoCallbackCookies(res.headers['set-cookie']);

      const sessionId = extractSessionIdFromSetCookie(res.headers['set-cookie']);
      const session = await deps.sessionStore.get(sessionId);

      expect(session).toMatchObject({
        userId: created.user.id,
        tenantId: tenant.id,
        tenantKey,
        membershipId: created.membership.id,
        role: 'USER',
        mfaVerified: true,
        emailVerified: true,
      });

      const audits = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('tenant_id', '=', tenant.id)
        .where('action', '=', 'auth.sso.login.success')
        .execute();

      expect(audits).toHaveLength(1);
      const meta = audits[0].metadata as Record<string, unknown>;
      expect(meta.email).toBeUndefined();
      expect(meta.provider).toBe('google');
    } finally {
      await close();
    }
  });

  it('success: ACTIVE agent → preserves canonical AGENT role in session', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const email = `agent-${randomUUID().slice(0, 8)}@example.com`;

      const created = await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'AGENT',
        status: 'ACTIVE',
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(302);
      expect(String(res.headers.location)).toContain('/auth/sso/done?nextAction=NONE');

      const sessionId = extractSessionIdFromSetCookie(res.headers['set-cookie']);
      const session = await deps.sessionStore.get(sessionId);

      expect(session).toMatchObject({
        userId: created.user.id,
        tenantId: tenant.id,
        tenantKey,
        membershipId: created.membership.id,
        role: 'AGENT',
        mfaVerified: true,
        emailVerified: true,
      });
    } finally {
      await close();
    }
  });

  it('success: legacy MEMBER membership read during SSO normalizes to USER in session', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const email = `legacy-member-${randomUUID().slice(0, 8)}@example.com`;

      const user = await deps.db
        .insertInto('users')
        .values({ email, name: 'Legacy Member SSO User', email_verified: true })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const membership = await deps.db
        .insertInto('memberships')
        .values({
          tenant_id: tenant.id,
          user_id: user.id,
          role: 'MEMBER',
          status: 'ACTIVE',
          accepted_at: new Date(),
        })
        .returning(['id'])
        .executeTakeFirstOrThrow();

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(302);
      expect(String(res.headers.location)).toContain('/auth/sso/done?nextAction=NONE');

      const sessionId = extractSessionIdFromSetCookie(res.headers['set-cookie']);
      const session = await deps.sessionStore.get(sessionId);

      expect(session).toMatchObject({
        userId: user.id,
        tenantId: tenant.id,
        tenantKey,
        membershipId: membership.id,
        role: 'USER',
        mfaVerified: true,
        emailVerified: true,
      });
    } finally {
      await close();
    }
  });

  it('success: ADMIN with verified MFA → 302 done?nextAction=MFA_REQUIRED', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const email = `admin-mfa-${randomUUID().slice(0, 8)}@example.com`;

      const created = await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'ADMIN',
        status: 'ACTIVE',
      });

      await deps.db
        .insertInto('mfa_secrets')
        .values({
          user_id: created.user.id,
          encrypted_secret: deps.encryptionService.encrypt('JBSWY3DPEHPK3PXP'),
          is_verified: true,
          verified_at: new Date(),
        })
        .execute();

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(302);
      expect(String(res.headers.location)).toContain('/auth/sso/done?nextAction=MFA_REQUIRED');
    } finally {
      await close();
    }
  });

  it('success: ADMIN without MFA → 302 done?nextAction=MFA_SETUP_REQUIRED', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const email = `admin-${randomUUID().slice(0, 8)}@example.com`;

      await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'ADMIN',
        status: 'ACTIVE',
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(302);
      expect(String(res.headers.location)).toContain(
        '/auth/sso/done?nextAction=MFA_SETUP_REQUIRED',
      );
      expect(res.headers['set-cookie']).toBeTruthy();
    } finally {
      await close();
    }
  });

  it('success: INVITED member → activates to ACTIVE → 302 success', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const email = `inv-${randomUUID().slice(0, 8)}@example.com`;

      const created = await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'USER',
        status: 'INVITED',
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(302);
      expect(String(res.headers.location)).toContain('/auth/sso/done?nextAction=NONE');

      const membership = await deps.db
        .selectFrom('memberships')
        .select(['status'])
        .where('id', '=', created.membership.id)
        .executeTakeFirstOrThrow();

      expect(membership.status).toBe('ACTIVE');
    } finally {
      await close();
    }
  });

  it('success: AGENT invite via SSO activates canonical AGENT membership and attaches Agent groups', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `agent-invite-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createSsoTenant({
        db: deps.db,
        tenantKey,
        allowedSso: ['google'],
        publicSignupEnabled: false,
        adminInviteRequired: true,
      });
      const agentGroup = await createAgentGroup({ db: deps.db, tenantId: tenant.id });
      const invite = await createInvite({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'AGENT',
      });
      await attachInviteAgentGroup({
        db: deps.db,
        tenantId: tenant.id,
        inviteId: invite.id,
        groupId: agentGroup.id,
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(302);
      expect(String(res.headers.location)).toContain('/auth/sso/done?nextAction=NONE');

      const user = await deps.db
        .selectFrom('users')
        .select(['id'])
        .where('email', '=', email)
        .executeTakeFirstOrThrow();
      const membership = await deps.db
        .selectFrom('memberships')
        .select(['id', 'role', 'status'])
        .where('tenant_id', '=', tenant.id)
        .where('user_id', '=', user.id)
        .executeTakeFirstOrThrow();
      expect(membership.role).toBe('AGENT');
      expect(membership.status).toBe('ACTIVE');

      const groupMembership = await deps.db
        .selectFrom('tenant_group_members')
        .select(['group_id', 'membership_id'])
        .where('tenant_id', '=', tenant.id)
        .where('group_id', '=', agentGroup.id)
        .where('membership_id', '=', membership.id)
        .executeTakeFirstOrThrow();
      expect(groupMembership).toEqual({
        group_id: agentGroup.id,
        membership_id: membership.id,
      });

      const sessionId = extractSessionIdFromSetCookie(res.headers['set-cookie']);
      const session = await deps.sessionStore.get(sessionId);
      expect(session).toMatchObject({
        userId: user.id,
        tenantId: tenant.id,
        tenantKey,
        membershipId: membership.id,
        role: 'AGENT',
        mfaVerified: true,
        emailVerified: true,
      });
    } finally {
      await close();
    }
  });

  it('409 when SSO Agent invite group revalidation fails and token remains pending', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `agent-archived-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createSsoTenant({
        db: deps.db,
        tenantKey,
        allowedSso: ['google'],
        publicSignupEnabled: false,
        adminInviteRequired: true,
      });
      const agentGroup = await createAgentGroup({ db: deps.db, tenantId: tenant.id });
      const invite = await createInvite({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'AGENT',
      });
      await attachInviteAgentGroup({
        db: deps.db,
        tenantId: tenant.id,
        inviteId: invite.id,
        groupId: agentGroup.id,
      });
      await deps.db
        .updateTable('tenant_groups')
        .set({ status: 'ARCHIVED', archived_at: new Date() })
        .where('id', '=', agentGroup.id)
        .execute();

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(409);
      expect(res.body).toContain('This Agent invitation no longer has an active Agent group');

      const inviteRow = await deps.db
        .selectFrom('invites')
        .select(['status', 'used_at'])
        .where('id', '=', invite.id)
        .executeTakeFirstOrThrow();
      expect(inviteRow.status).toBe('PENDING');
      expect(inviteRow.used_at).toBeNull();

      const users = await deps.db
        .selectFrom('users')
        .select(['id'])
        .where('email', '=', email)
        .execute();
      expect(users).toHaveLength(0);

      const groupMembers = await deps.db
        .selectFrom('tenant_group_members')
        .select(['group_id'])
        .where('tenant_id', '=', tenant.id)
        .where('group_id', '=', agentGroup.id)
        .execute();
      expect(groupMembers).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('403 when provider not in tenant.allowedSso + failure audit written', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });
      const state = 'provider-not-allowed-google';
      const cookieHeader = `sso-state=${state}`;

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(403);

      const audits = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('tenant_id', '=', tenant.id)
        .where('action', '=', 'auth.sso.login.failed')
        .execute();

      expect(audits).toHaveLength(1);
      const meta = audits[0].metadata as Record<string, unknown>;
      expect(meta.provider).toBe('google');
      expect(meta.reason).toBe('provider_not_allowed');
    } finally {
      await close();
    }
  });

  it('403 when email domain not allowed', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createSsoTenant({
        db: deps.db,
        tenantKey,
        allowedSso: ['google'],
        allowedEmailDomains: ['acme.com'],
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email: `u-${randomUUID().slice(0, 8)}@gmail.com`,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('success: public-signup-allowed new SSO user → creates ACTIVE membership without orphaning policy flow', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `signup-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createSsoTenant({
        db: deps.db,
        tenantKey,
        allowedSso: ['google'],
        publicSignupEnabled: true,
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(302);
      expect(String(res.headers.location)).toContain('/auth/sso/done?nextAction=NONE');

      const user = await deps.db
        .selectFrom('users')
        .select(['id'])
        .where('email', '=', email)
        .executeTakeFirst();
      expect(user).toBeTruthy();

      const membership = await deps.db
        .selectFrom('memberships')
        .select(['status', 'tenant_id', 'role'])
        .where('user_id', '=', user!.id)
        .executeTakeFirst();
      expect(membership).toEqual({ status: 'ACTIVE', tenant_id: tenant.id, role: 'USER' });
    } finally {
      await close();
    }
  });

  it('403 when no membership and self-signup path is blocked, and does not create an orphan user row', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `blocked-${randomUUID().slice(0, 8)}@example.com`;

    try {
      await createSsoTenant({
        db: deps.db,
        tenantKey,
        allowedSso: ['google'],
        publicSignupEnabled: false,
        adminInviteRequired: true,
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json()).toEqual({
        error: {
          code: 'FORBIDDEN',
          message: 'Sign up is disabled. You need an invitation to join.',
        },
      });

      const users = await deps.db
        .selectFrom('users')
        .select(['id'])
        .where('email', '=', email)
        .execute();
      expect(users).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('success: valid invite + SSO callback → consumes invite and activates tenant access', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `invite-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createSsoTenant({
        db: deps.db,
        tenantKey,
        allowedSso: ['google'],
        publicSignupEnabled: false,
        adminInviteRequired: true,
      });

      const invite = await createInvite({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'ADMIN',
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(302);
      expect(String(res.headers.location)).toContain(
        '/auth/sso/done?nextAction=MFA_SETUP_REQUIRED',
      );

      const inviteRow = await deps.db
        .selectFrom('invites')
        .select(['status', 'used_at'])
        .where('id', '=', invite.id)
        .executeTakeFirstOrThrow();
      expect(inviteRow.status).toBe('ACCEPTED');
      expect(inviteRow.used_at).not.toBeNull();

      const user = await deps.db
        .selectFrom('users')
        .select(['id'])
        .where('email', '=', email)
        .executeTakeFirstOrThrow();

      const membership = await deps.db
        .selectFrom('memberships')
        .select(['status', 'role'])
        .where('user_id', '=', user.id)
        .where('tenant_id', '=', tenant.id)
        .executeTakeFirstOrThrow();
      expect(membership).toEqual({ status: 'ACTIVE', role: 'ADMIN' });
    } finally {
      await close();
    }
  });

  it('409 when invite state is expired, and the blocked callback path does not create an orphan user row', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;
    const email = `expired-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createSsoTenant({
        db: deps.db,
        tenantKey,
        allowedSso: ['google'],
        publicSignupEnabled: false,
        adminInviteRequired: true,
      });

      await createInvite({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'USER',
        status: 'PENDING',
        expiresAt: new Date(Date.now() - 60_000),
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(409);
      expect(res.json()).toEqual({
        error: {
          code: 'CONFLICT',
          message: 'This invitation link has expired. Contact your admin.',
        },
      });

      const users = await deps.db
        .selectFrom('users')
        .select(['id'])
        .where('email', '=', email)
        .execute();
      expect(users).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('403 when no membership for tenant', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email: `u-${randomUUID().slice(0, 8)}@example.com`,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('403 when membership is SUSPENDED', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const email = `u-${randomUUID().slice(0, 8)}@example.com`;

      await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'USER',
        status: 'SUSPENDED',
      });

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `g-sub-${randomUUID()}`,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('403 when subject drift (different sub for same user/provider)', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const email = `u-${randomUUID().slice(0, 8)}@example.com`;

      const { user } = await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'USER',
        status: 'ACTIVE',
      });

      const existingSub = `g-existing-${randomUUID()}`;
      const tokenSub = `g-token-${randomUUID()}`;

      await deps.db
        .insertInto('auth_identities')
        .values({
          user_id: user.id,
          provider: 'google',
          provider_subject: existingSub,
          password_hash: null,
        })
        .execute();

      const { state, nonce, cookieHeader } = await getSsoStateFromStart({
        app,
        host,
        provider: 'google',
      });

      sso.googleAdapter.willSucceed({
        idToken: buildFakeIdToken({
          iss: 'https://accounts.google.com',
          aud: GOOGLE_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: tokenSub,
          email,
          email_verified: true,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host, cookie: cookieHeader },
      });

      expect(res.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('400 when invalid/expired state', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?code=fake-code&state=not-a-real-state`,
        headers: { host },
      });

      expect(res.statusCode).toBe(400);
    } finally {
      await close();
    }
  });

  it('400 when missing code parameter', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/google/callback?state=anything`,
        headers: { host },
      });

      expect(res.statusCode).toBe(400);
    } finally {
      await close();
    }
  });
});
