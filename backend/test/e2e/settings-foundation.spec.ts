import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import { describe, expect, it } from 'vitest';

import { SettingsFoundationRepo } from '../../src/modules/settings/dal/settings-foundation.repo';
import { runDevSeed } from '../../src/shared/db/seed/dev-seed';
import {
  down as downSettingsFoundationMigration,
  up as upSettingsFoundationMigration,
} from '../../src/shared/db/migrations/0017_settings_foundation';
import { up as upSettingsAccountMigration } from '../../src/shared/db/migrations/0018_settings_account';
import type { DbExecutor } from '../../src/shared/db/db';
import { buildTestApp } from '../helpers/build-test-app';
import { createAdminSession } from '../helpers/create-admin-session';

function hostForTenant(tenantKey: string): string {
  return `${tenantKey}.hubins.com`;
}

async function createTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  setupCompletedAt?: Date | null;
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: false,
      admin_invite_required: false,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
      allowed_sso: [],
      setup_completed_at: opts.setupCompletedAt ?? null,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

async function createCpProvisioning(opts: {
  db: DbExecutor;
  tenantId: string;
  accountKey: string;
  cpRevision: number;
}) {
  const account = await opts.db
    .insertInto('cp_accounts')
    .values({
      account_name: `Account ${opts.accountKey}`,
      account_key: opts.accountKey,
      cp_status: 'Active',
      cp_revision: opts.cpRevision,
      access_configured: true,
      account_settings_configured: true,
      module_settings_configured: true,
      integrations_configured: false,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  await opts.db
    .insertInto('cp_account_provisioning')
    .values({
      account_id: account.id,
      tenant_id: opts.tenantId,
      last_published_status: 'Active',
      published_at: new Date(),
    })
    .execute();

  return account;
}

describe('settings phase 1 foundation schema and rollout bridge', () => {
  it('backfills legacy workspace acknowledgement conservatively during migration', async () => {
    const { deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await downSettingsFoundationMigration(deps.db);

      const acknowledgedAt = new Date('2026-04-20T10:15:00.000Z');
      const tenant = await createTenant({
        db: deps.db,
        tenantKey: `legacy-${randomUUID().slice(0, 8)}`,
        setupCompletedAt: acknowledgedAt,
      });
      await createCpProvisioning({
        db: deps.db,
        tenantId: tenant.id,
        accountKey: `legacy-cp-${randomUUID().slice(0, 8)}`,
        cpRevision: 7,
      });

      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const repo = new SettingsFoundationRepo(deps.db);
      const aggregate = await repo.findAggregateState(tenant.id);
      const sections = await repo.listSectionStates(tenant.id);

      expect(aggregate).toMatchObject({
        tenantId: tenant.id,
        overallStatus: 'IN_PROGRESS',
        version: 1,
        appliedCpRevision: 7,
        lastTransitionReasonCode: 'LEGACY_AUTH_ACK_BRIDGE',
      });
      expect(aggregate?.lastTransitionAt.toISOString()).toBe(acknowledgedAt.toISOString());

      expect(sections).toHaveLength(4);
      expect(sections).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            sectionKey: 'access',
            status: 'COMPLETE',
            version: 1,
            appliedCpRevision: 7,
            lastTransitionReasonCode: 'LEGACY_AUTH_ACK_BRIDGE',
          }),
          expect.objectContaining({
            sectionKey: 'account',
            status: 'NOT_STARTED',
            version: 1,
            appliedCpRevision: 7,
            lastTransitionReasonCode: 'FOUNDATION_INITIALIZED',
          }),
          expect.objectContaining({
            sectionKey: 'personal',
            status: 'NOT_STARTED',
            version: 1,
            appliedCpRevision: 7,
            lastTransitionReasonCode: 'FOUNDATION_INITIALIZED',
          }),
          expect.objectContaining({
            sectionKey: 'integrations',
            status: 'NOT_STARTED',
            version: 1,
            appliedCpRevision: 7,
            lastTransitionReasonCode: 'FOUNDATION_INITIALIZED',
          }),
        ]),
      );
      expect(aggregate?.overallStatus).not.toBe('COMPLETE');
    } finally {
      await close();
    }
  });

  it('bridges the legacy auth acknowledgement into native foundation rows without fake completion', async () => {
    const { app, deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const tenant = await createTenant({
        db: deps.db,
        tenantKey: `ack-${randomUUID().slice(0, 8)}`,
      });
      const admin = await createAdminSession({
        app,
        deps,
        tenantId: tenant.id,
        tenantKey: tenant.key,
        email: `admin-${randomUUID().slice(0, 8)}@example.com`,
        password: 'Password123!',
      });

      const firstAckRes = await app.inject({
        method: 'POST',
        url: '/auth/workspace-setup-ack',
        headers: {
          host: hostForTenant(tenant.key),
          cookie: admin.cookie,
        },
      });

      expect(firstAckRes.statusCode).toBe(200);
      expect(firstAckRes.json()).toEqual({ status: 'ACKNOWLEDGED' });

      const secondAckRes = await app.inject({
        method: 'POST',
        url: '/auth/workspace-setup-ack',
        headers: {
          host: hostForTenant(tenant.key),
          cookie: admin.cookie,
        },
      });

      expect(secondAckRes.statusCode).toBe(200);

      const tenantRow = await deps.db
        .selectFrom('tenants')
        .select(['setup_completed_at'])
        .where('id', '=', tenant.id)
        .executeTakeFirstOrThrow();

      expect(tenantRow.setup_completed_at).not.toBeNull();

      const repo = new SettingsFoundationRepo(deps.db);
      const aggregate = await repo.findAggregateState(tenant.id);
      const sections = await repo.listSectionStates(tenant.id);
      const access = sections.find((section) => section.sectionKey === 'access');
      const account = sections.find((section) => section.sectionKey === 'account');
      const personal = sections.find((section) => section.sectionKey === 'personal');
      const integrations = sections.find((section) => section.sectionKey === 'integrations');

      expect(aggregate).toMatchObject({
        overallStatus: 'IN_PROGRESS',
        version: 2,
        appliedCpRevision: 0,
        lastTransitionReasonCode: 'LEGACY_AUTH_ACK_BRIDGE',
      });
      expect(access).toMatchObject({
        status: 'COMPLETE',
        version: 2,
        appliedCpRevision: 0,
        lastTransitionReasonCode: 'LEGACY_AUTH_ACK_BRIDGE',
        lastReviewedByUserId: admin.userId,
      });
      expect(account).toMatchObject({ status: 'NOT_STARTED', version: 1, appliedCpRevision: 0 });
      expect(personal).toMatchObject({
        status: 'NOT_STARTED',
        version: 1,
        appliedCpRevision: 0,
      });
      expect(integrations).toMatchObject({
        status: 'NOT_STARTED',
        version: 1,
        appliedCpRevision: 0,
      });
      expect(aggregate?.overallStatus).not.toBe('COMPLETE');
    } finally {
      await close();
    }
  });

  it('initialises foundation rows for both bootstrap and dev-seeded tenants', async () => {
    const { deps, close, reset } = await buildTestApp();

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      await runDevSeed({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        passwordHasher: deps.passwordHasher,
        options: {
          tenantKey: 'goodwill-ca',
          tenantName: 'GoodWill California',
          adminEmail: 'system_admin@example.com',
          inviteTtlHours: 24 * 7,
        },
      });

      const tenants = await deps.db
        .selectFrom('tenants')
        .select(['id', 'key'])
        .where('key', 'in', ['goodwill-ca', 'goodwill-open'])
        .orderBy('key asc')
        .execute();

      expect(tenants.map((tenant) => tenant.key)).toEqual(['goodwill-ca', 'goodwill-open']);

      const repo = new SettingsFoundationRepo(deps.db);
      for (const tenant of tenants) {
        const aggregate = await repo.findAggregateState(tenant.id);
        const sections = await repo.listSectionStates(tenant.id);

        expect(aggregate).toMatchObject({
          tenantId: tenant.id,
          overallStatus: 'NOT_STARTED',
          version: 1,
          appliedCpRevision: 0,
          lastTransitionReasonCode: 'TENANT_BOOTSTRAP_FOUNDATION',
        });
        expect(sections).toHaveLength(4);
        expect(sections.every((section) => section.status === 'NOT_STARTED')).toBe(true);
        expect(sections.every((section) => section.appliedCpRevision === 0)).toBe(true);
      }
    } finally {
      await close();
    }
  });

  it('creates native foundation rows when CP publish provisions a tenant', async () => {
    const { app, deps, close, reset } = await buildTestApp();
    const accountKey = `phase1-${randomUUID().slice(0, 8)}`;

    try {
      await reset();
      await upSettingsFoundationMigration(deps.db);
      await upSettingsAccountMigration(deps.db);

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'Phase 1 Publish Tenant',
          accountKey,
        },
      });
      expect(createRes.statusCode).toBe(201);

      const accessRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/access`,
        payload: {
          loginMethods: {
            password: true,
            google: false,
            microsoft: false,
          },
          mfaPolicy: {
            adminRequired: true,
            memberRequired: false,
          },
          signupPolicy: {
            publicSignup: false,
            adminInvitationsAllowed: true,
            allowedDomains: [],
          },
        },
      });
      expect(accessRes.statusCode).toBe(200);

      const accountSettingsRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/account-settings`,
        payload: {
          branding: {
            logo: true,
            menuColor: true,
            fontColor: true,
            welcomeMessage: true,
          },
          organizationStructure: {
            employers: true,
            locations: true,
          },
          companyCalendar: {
            allowed: true,
          },
        },
      });
      expect(accountSettingsRes.statusCode).toBe(200);

      const modulesRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/modules`,
        payload: {
          modules: {
            personal: false,
            documents: false,
            benefits: false,
            payments: false,
          },
        },
      });
      expect(modulesRes.statusCode).toBe(200);

      const publishRes = await app.inject({
        method: 'POST',
        url: `/cp/accounts/${accountKey}/publish`,
        payload: {
          targetStatus: 'Active',
        },
      });
      expect(publishRes.statusCode).toBe(200);

      const provisioning = await deps.db
        .selectFrom('cp_account_provisioning as provisioning')
        .innerJoin('cp_accounts as account', 'account.id', 'provisioning.account_id')
        .select(['provisioning.tenant_id as tenant_id', 'account.cp_revision as cp_revision'])
        .where('account.account_key', '=', accountKey)
        .executeTakeFirstOrThrow();

      const repo = new SettingsFoundationRepo(deps.db);
      const aggregate = await repo.findAggregateState(provisioning.tenant_id);
      const sections = await repo.listSectionStates(provisioning.tenant_id);

      expect(aggregate).toMatchObject({
        tenantId: provisioning.tenant_id,
        overallStatus: 'NOT_STARTED',
        version: 1,
        appliedCpRevision: provisioning.cp_revision,
        lastTransitionReasonCode: 'CP_PROVISIONING_FOUNDATION',
      });
      expect(sections).toHaveLength(4);
      expect(
        sections.map((section) => ({
          sectionKey: section.sectionKey,
          status: section.status,
          appliedCpRevision: section.appliedCpRevision,
          lastTransitionReasonCode: section.lastTransitionReasonCode,
        })),
      ).toEqual([
        {
          sectionKey: 'access',
          status: 'NOT_STARTED',
          appliedCpRevision: provisioning.cp_revision,
          lastTransitionReasonCode: 'CP_PROVISIONING_FOUNDATION',
        },
        {
          sectionKey: 'account',
          status: 'NOT_STARTED',
          appliedCpRevision: provisioning.cp_revision,
          lastTransitionReasonCode: 'CP_PROVISIONING_FOUNDATION',
        },
        {
          sectionKey: 'integrations',
          status: 'NOT_STARTED',
          appliedCpRevision: provisioning.cp_revision,
          lastTransitionReasonCode: 'CP_PROVISIONING_FOUNDATION',
        },
        {
          sectionKey: 'personal',
          status: 'NOT_STARTED',
          appliedCpRevision: provisioning.cp_revision,
          lastTransitionReasonCode: 'CP_PROVISIONING_FOUNDATION',
        },
      ]);
    } finally {
      await close();
    }
  });
});
