import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { buildTestApp } from '../helpers/build-test-app';
import {
  buildFakeIdToken,
  createSsoTenant,
  createUserWithMembership,
  getSsoStateFromStart,
} from '../helpers/sso-test-fixtures';

const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID ?? 'test-microsoft-client-id';

function msIssuer(tid: string): string {
  return `https://login.microsoftonline.com/${tid}/v2.0`;
}

describe('GET /auth/sso/microsoft/callback', () => {
  it('success: ACTIVE member → 302 done?nextAction=NONE + sets session cookie + audit written', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });

      const email = `u-${randomUUID().slice(0, 8)}@example.com`;
      await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        status: 'ACTIVE',
      });

      const { state, nonce } = await getSsoStateFromStart({ app, host, provider: 'microsoft' });

      const tid = `tenant-${randomUUID().slice(0, 8)}`;

      sso.microsoftAdapter.willSucceed({
        idToken: buildFakeIdToken({
          tid,
          iss: msIssuer(tid),
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `ms-sub-${randomUUID()}`, // full UUID (no slice)
          preferred_username: email,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/microsoft/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host },
      });

      expect(res.statusCode).toBe(302);
      expect(String(res.headers.location)).toContain('/auth/sso/done?nextAction=NONE');
      expect(res.headers['set-cookie']).toBeTruthy();

      // Audit: success event written, scoped to tenant
      const audits = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('tenant_id', '=', tenant.id)
        .where('action', '=', 'auth.sso.login.success')
        .execute();
      expect(audits).toHaveLength(1);

      // PII hardening: success audit must not include raw email
      const meta = audits[0].metadata as Record<string, unknown>;
      expect(meta.email).toBeUndefined();
      expect(meta.provider).toBe('microsoft');
    } finally {
      await close();
    }
  });

  it('success: ADMIN without MFA → 302 done?nextAction=MFA_SETUP_REQUIRED', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });
      const email = `admin-${randomUUID().slice(0, 8)}@example.com`;

      await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'ADMIN',
        status: 'ACTIVE',
      });

      const { state, nonce } = await getSsoStateFromStart({ app, host, provider: 'microsoft' });
      const tid = `tenant-${randomUUID().slice(0, 8)}`;

      sso.microsoftAdapter.willSucceed({
        idToken: buildFakeIdToken({
          tid,
          iss: msIssuer(tid),
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `ms-sub-${randomUUID()}`, // full UUID (no slice)
          preferred_username: email,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/microsoft/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host },
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
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });
      const email = `inv-${randomUUID().slice(0, 8)}@example.com`;

      const created = await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        status: 'INVITED',
      });

      const { state, nonce } = await getSsoStateFromStart({ app, host, provider: 'microsoft' });
      const tid = `tenant-${randomUUID().slice(0, 8)}`;

      sso.microsoftAdapter.willSucceed({
        idToken: buildFakeIdToken({
          tid,
          iss: msIssuer(tid),
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `ms-sub-${randomUUID()}`, // full UUID (no slice)
          preferred_username: email,
        }),
      });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/microsoft/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host },
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

  it('403 when provider not in tenant.allowedSso + failure audit written', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['google'] });
      const { state } = await getSsoStateFromStart({ app, host, provider: 'microsoft' });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/microsoft/callback?code=fake-code&state=${encodeURIComponent(state)}`,
        headers: { host },
      });

      expect(res.statusCode).toBe(403);

      // Audit: failure event written even when denied before user resolution
      const audits = await deps.db
        .selectFrom('audit_events')
        .selectAll()
        .where('tenant_id', '=', tenant.id)
        .where('action', '=', 'auth.sso.login.failed')
        .execute();
      expect(audits).toHaveLength(1);

      const meta = audits[0].metadata as Record<string, unknown>;
      expect(meta.provider).toBe('microsoft');
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
        allowedSso: ['microsoft'],
        allowedEmailDomains: ['acme.com'],
      });

      const { state, nonce } = await getSsoStateFromStart({ app, host, provider: 'microsoft' });
      const tid = `tenant-${randomUUID().slice(0, 8)}`;

      sso.microsoftAdapter.willSucceed({
        idToken: buildFakeIdToken({
          tid,
          iss: msIssuer(tid),
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `ms-sub-${randomUUID()}`, // full UUID (no slice)
          preferred_username: `u-${randomUUID().slice(0, 8)}@gmail.com`,
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

  it('403 when no membership for tenant', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });
      const { state, nonce } = await getSsoStateFromStart({ app, host, provider: 'microsoft' });
      const tid = `tenant-${randomUUID().slice(0, 8)}`;

      sso.microsoftAdapter.willSucceed({
        idToken: buildFakeIdToken({
          tid,
          iss: msIssuer(tid),
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `ms-sub-${randomUUID()}`, // full UUID (no slice)
          preferred_username: `u-${randomUUID().slice(0, 8)}@example.com`,
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

  it('403 when membership is SUSPENDED', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });
      const email = `u-${randomUUID().slice(0, 8)}@example.com`;

      await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        status: 'SUSPENDED',
      });

      const { state, nonce } = await getSsoStateFromStart({ app, host, provider: 'microsoft' });
      const tid = `tenant-${randomUUID().slice(0, 8)}`;

      sso.microsoftAdapter.willSucceed({
        idToken: buildFakeIdToken({
          tid,
          iss: msIssuer(tid),
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: `ms-sub-${randomUUID()}`, // full UUID (no slice)
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

  it('403 when subject drift (different sub for same user/provider)', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });
      const email = `u-${randomUUID().slice(0, 8)}@example.com`;

      const { user } = await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        status: 'ACTIVE',
      });

      // Existing SSO identity with a different provider_subject.
      // (provider, provider_subject) is UNIQUE in DB, so ensure it's unique per test.
      const existingSub = `ms-existing-${randomUUID()}`;
      const tokenSub = `ms-token-${randomUUID()}`;

      await deps.db
        .insertInto('auth_identities')
        .values({
          user_id: user.id,
          provider: 'microsoft',
          provider_subject: existingSub,
          password_hash: null,
        })
        .execute();

      const { state, nonce } = await getSsoStateFromStart({ app, host, provider: 'microsoft' });
      const tid = `tenant-${randomUUID().slice(0, 8)}`;

      sso.microsoftAdapter.willSucceed({
        idToken: buildFakeIdToken({
          tid,
          iss: msIssuer(tid),
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce,
          sub: tokenSub, // drift vs existingSub
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

  it('400 when invalid/expired state', async () => {
    const { app, deps, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/microsoft/callback?code=fake-code&state=not-a-real-state`,
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
      await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });

      const res = await app.inject({
        method: 'GET',
        url: `/auth/sso/microsoft/callback?state=anything`,
        headers: { host },
      });

      expect(res.statusCode).toBe(400);
    } finally {
      await close();
    }
  });

  it('401 when nonce mismatch', async () => {
    const { app, deps, sso, close } = await buildTestApp();
    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    try {
      const tenant = await createSsoTenant({ db: deps.db, tenantKey, allowedSso: ['microsoft'] });
      const email = `u-${randomUUID().slice(0, 8)}@example.com`;

      await createUserWithMembership({
        db: deps.db,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        status: 'ACTIVE',
      });

      const { state } = await getSsoStateFromStart({ app, host, provider: 'microsoft' });
      const tid = `tenant-${randomUUID().slice(0, 8)}`;

      sso.microsoftAdapter.willSucceed({
        idToken: buildFakeIdToken({
          tid,
          iss: msIssuer(tid),
          aud: MICROSOFT_CLIENT_ID,
          exp: Math.floor(Date.now() / 1000) + 60,
          nonce: 'wrong-nonce',
          sub: `ms-sub-${randomUUID()}`, // full UUID (no slice)
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
});
