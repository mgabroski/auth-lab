import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';
import { hostForTenant } from '../helpers/tenant-host';
import type { AppDeps } from '../../src/app/di';
import type { MembershipRole } from '../../src/modules/memberships/membership.types';
import { getSessionCookieName } from '../../src/shared/session/session.types';

const sessionCookieName = getSessionCookieName(false);

async function createTenant(deps: AppDeps): Promise<{ id: string; key: string }> {
  const key = `guard-${randomUUID().slice(0, 8)}`;

  return deps.db
    .insertInto('tenants')
    .values({
      key,
      name: `Guard Tenant ${key}`,
      is_active: true,
      public_signup_enabled: false,
      admin_invite_required: false,
      member_mfa_required: false,
      allowed_email_domains: [],
      allowed_sso: [],
      setup_completed_at: null,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

async function createSession(opts: {
  deps: AppDeps;
  tenantId: string;
  tenantKey: string;
  role: MembershipRole;
}): Promise<{ cookie: string }> {
  const user = await opts.deps.db
    .insertInto('users')
    .values({
      email: `${opts.role.toLowerCase()}-${randomUUID().slice(0, 8)}@example.com`,
      name: `${opts.role} Guard User`,
      email_verified: true,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const membership = await opts.deps.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: opts.role,
      status: 'ACTIVE',
      accepted_at: new Date(),
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  const sessionId = await opts.deps.sessionStore.create({
    tenantId: opts.tenantId,
    tenantKey: opts.tenantKey,
    userId: user.id,
    membershipId: membership.id,
    role: opts.role,
    mfaVerified: true,
    emailVerified: true,
    createdAt: new Date().toISOString(),
  });

  return { cookie: `${sessionCookieName}=${sessionId}` };
}

describe('backend admin-only guard boundaries', () => {
  it('rejects AGENT and USER sessions on admin invite, Settings, and People & Teams surfaces', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      const tenant = await createTenant(deps);

      for (const role of ['AGENT', 'USER'] as const) {
        const session = await createSession({
          deps,
          tenantId: tenant.id,
          tenantKey: tenant.key,
          role,
        });

        const routes = [
          { method: 'GET' as const, url: '/settings/overview' },
          { method: 'GET' as const, url: '/settings/access' },
          { method: 'GET' as const, url: '/admin/invites?limit=20&offset=0' },
          { method: 'GET' as const, url: '/people-teams/groups' },
        ];

        for (const route of routes) {
          const res = await app.inject({
            method: route.method,
            url: route.url,
            headers: { host: hostForTenant(tenant.key), cookie: session.cookie },
          });

          expect(res.statusCode, `${role} ${route.url}`).toBe(403);
          expect(res.body, `${role} ${route.url}`).toContain('Insufficient role');
        }
      }
    } finally {
      await close();
    }
  });
});
