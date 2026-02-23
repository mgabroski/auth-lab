import { describe, it, expect, vi } from 'vitest';

// ✅ MUST BE BEFORE importing the provider module in ESM projects
vi.mock('../../src/modules/auth/sso/microsoft/microsoft-sso.provider', async () => {
  const actual = await vi.importActual<
    typeof import('../../src/modules/auth/sso/microsoft/microsoft-sso.provider')
  >('../../src/modules/auth/sso/microsoft/microsoft-sso.provider');

  return {
    ...actual,
    exchangeMicrosoftAuthorizationCode: vi.fn(),
  };
});

import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import type { FastifyInstance } from 'fastify';
import type { Response } from 'light-my-request';

import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';

// import AFTER vi.mock()
import * as microsoftProvider from '../../src/modules/auth/sso/microsoft/microsoft-sso.provider';

const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID ?? 'test-microsoft-client-id';

function base64UrlJson(value: unknown): string {
  const raw = Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
  return raw.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function buildFakeIdToken(payload: Record<string, unknown>): string {
  const header = { alg: 'none', typ: 'JWT' };
  // 3 parts to look like a real JWT
  return `${base64UrlJson(header)}.${base64UrlJson(payload)}.fake_signature`;
}

async function createTenant(opts: { db: DbExecutor; tenantKey: string; allowedSso: string[] }) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: false,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
      allowed_sso: opts.allowedSso,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

async function createUser(opts: { db: DbExecutor; email: string; name?: string }) {
  return opts.db
    .insertInto('users')
    .values({
      email: opts.email,
      name: opts.name ?? null,
    })
    .returning(['id', 'email'])
    .executeTakeFirstOrThrow();
}

async function createMembership(opts: {
  db: DbExecutor;
  tenantId: string;
  userId: string;
  role: 'ADMIN' | 'MEMBER';
  status: 'ACTIVE' | 'INVITED' | 'SUSPENDED';
}) {
  return opts.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: opts.userId,
      role: opts.role,
      status: opts.status,
      invited_at: new Date(),
      ...(opts.status === 'ACTIVE' ? { accepted_at: new Date() } : {}),
      ...(opts.status === 'SUSPENDED' ? { suspended_at: new Date() } : {}),
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();
}

async function getStateFromStart(opts: {
  app: FastifyInstance;
  host: string;
}): Promise<{ state: string; nonce: string }> {
  const res: Response = await opts.app.inject({
    method: 'GET',
    url: '/auth/sso/microsoft',
    headers: { host: opts.host },
  });

  expect(res.statusCode).toBe(302);

  const location = res.headers.location;
  if (typeof location !== 'string') {
    throw new Error('Location header missing in 302 response');
  }

  const u = new URL(location, `http://${opts.host}`);
  const state = u.searchParams.get('state');
  const nonce = u.searchParams.get('nonce');

  expect(state).toBeTruthy();
  expect(nonce).toBeTruthy();

  if (typeof state !== 'string' || typeof nonce !== 'string') {
    throw new Error('state/nonce query params missing in SSO redirect URL');
  }

  return { state, nonce };
}

describe('GET /auth/sso/microsoft/callback', () => {
  it('success: ACTIVE membership → 302 done?nextAction=NONE + sets session cookie', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createTenant({
        db: deps.db,
        tenantKey,
        allowedSso: ['google', 'microsoft'],
      });

      const email = `u-${randomUUID().slice(0, 8)}@example.com`;
      const user = await createUser({ db: deps.db, email });

      await createMembership({
        db: deps.db,
        tenantId: tenant.id,
        userId: user.id,
        role: 'MEMBER',
        status: 'ACTIVE',
      });

      const { state, nonce } = await getStateFromStart({ app, host });

      const sub = `ms-sub-${randomUUID().slice(0, 10)}`; // ✅ avoid unique constraint collisions across runs

      vi.mocked(microsoftProvider.exchangeMicrosoftAuthorizationCode).mockResolvedValueOnce({
        idToken: buildFakeIdToken({
          iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
          tid: 'tenant-123',
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub,
          preferred_username: email,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/microsoft/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host },
      });

      if (res.statusCode !== 302) {
        throw new Error(`Expected 302, got ${res.statusCode}. Body: ${res.body}`);
      }

      expect(res.headers.location).toContain('/auth/sso/done?nextAction=NONE');
      expect(res.headers['set-cookie']).toBeTruthy();
    } finally {
      await close();
    }
  });

  it('403 when provider not allowed for tenant', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const { state } = await getStateFromStart({ app, host });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/microsoft/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host },
      });

      expect(res.statusCode).toBe(403);
    } finally {
      await close();
    }
  });

  it('401 when nonce mismatch', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });

      const email = `u-${randomUUID().slice(0, 8)}@example.com`;
      const user = await createUser({ db: deps.db, email });

      await createMembership({
        db: deps.db,
        tenantId: tenant.id,
        userId: user.id,
        role: 'MEMBER',
        status: 'ACTIVE',
      });

      const { state } = await getStateFromStart({ app, host });

      const sub = `ms-sub-${randomUUID().slice(0, 10)}`; // ✅ future-proof

      vi.mocked(microsoftProvider.exchangeMicrosoftAuthorizationCode).mockResolvedValueOnce({
        idToken: buildFakeIdToken({
          iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
          tid: 'tenant-123',
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce: 'wrong-nonce',
          sub,
          preferred_username: email,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/microsoft/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await close();
    }
  });

  it('403 when membership is SUSPENDED', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });

      const email = `u-${randomUUID().slice(0, 8)}@example.com`;
      const user = await createUser({ db: deps.db, email });

      await createMembership({
        db: deps.db,
        tenantId: tenant.id,
        userId: user.id,
        role: 'MEMBER',
        status: 'SUSPENDED',
      });

      const { state, nonce } = await getStateFromStart({ app, host });

      const sub = `ms-sub-${randomUUID().slice(0, 10)}`; // ✅ avoid collisions across runs

      vi.mocked(microsoftProvider.exchangeMicrosoftAuthorizationCode).mockResolvedValueOnce({
        idToken: buildFakeIdToken({
          iss: 'https://login.microsoftonline.com/tenant-123/v2.0',
          tid: 'tenant-123',
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub,
          preferred_username: email,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/microsoft/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host },
      });

      expect(res.statusCode).toBe(403);
    } finally {
      await close();
    }
  });
});
