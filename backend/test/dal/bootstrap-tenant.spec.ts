import { describe, expect, it } from 'vitest';

import { runTenantBootstrap } from '../../src/shared/db/seed/bootstrap-tenant';
import { buildTestApp } from '../helpers/build-test-app';
import { getLatestOutboxPayload } from '../helpers/outbox-test-helpers';

describe('tenant bootstrap', () => {
  it('creates only the target tenant + bootstrap admin invite and omits raw token logging for operator mode', async () => {
    const tenantKey = 'bootstrap-qa';
    const tenantName = 'Bootstrap QA';
    const adminEmail = 'qa-admin@example.com';
    const logEntries: Array<Record<string, unknown>> = [];

    const { deps, close } = await buildTestApp();

    try {
      await runTenantBootstrap({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        outboxRepo: deps.outboxRepo,
        outboxEncryption: deps.outboxEncryption,
        options: {
          tenantKey,
          tenantName,
          adminEmail,
          inviteTtlHours: 72,
          emitRawInviteTokenToLogs: false,
          logInfo: (entry) => {
            logEntries.push(entry);
          },
        },
      });

      await runTenantBootstrap({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        outboxRepo: deps.outboxRepo,
        outboxEncryption: deps.outboxEncryption,
        options: {
          tenantKey,
          tenantName,
          adminEmail,
          inviteTtlHours: 72,
          emitRawInviteTokenToLogs: false,
          logInfo: (entry) => {
            logEntries.push(entry);
          },
        },
      });

      const tenant = await deps.db
        .selectFrom('tenants')
        .select(['id', 'key', 'public_signup_enabled'])
        .where('key', '=', tenantKey)
        .executeTakeFirstOrThrow();

      expect(tenant).toMatchObject({
        key: tenantKey,
        public_signup_enabled: false,
      });

      const bootstrapTenantId = tenant.id;

      const invites = await deps.db
        .selectFrom('invites')
        .select(['id', 'status', 'role', 'email', 'tenant_id'])
        .where('tenant_id', '=', bootstrapTenantId)
        .where('email', '=', adminEmail.toLowerCase())
        .where('role', '=', 'ADMIN')
        .execute();

      expect(invites).toHaveLength(1);
      expect(invites[0]).toMatchObject({
        status: 'PENDING',
        role: 'ADMIN',
        email: adminEmail.toLowerCase(),
        tenant_id: bootstrapTenantId,
      });

      const outbox = await getLatestOutboxPayload({
        db: deps.db,
        outboxEncryption: deps.outboxEncryption,
        type: 'invite.created',
        tenantKey,
      });

      expect(outbox.toEmail).toBe(adminEmail.toLowerCase());
      expect(outbox.idempotencyKey).toBe(
        `seed.invite.created:${bootstrapTenantId}:${adminEmail.toLowerCase()}`,
      );

      const memberUser = await deps.db
        .selectFrom('users')
        .select(['id'])
        .where('email', '=', 'member@example.com')
        .executeTakeFirst();

      if (memberUser) {
        const memberMembershipInBootstrapTenant = await deps.db
          .selectFrom('memberships')
          .select(['id'])
          .where('tenant_id', '=', bootstrapTenantId)
          .where('user_id', '=', memberUser.id)
          .executeTakeFirst();

        expect(memberMembershipInBootstrapTenant).toBeUndefined();
      }

      const createdInviteLog = logEntries.find((entry) => entry.msg === 'seed.invite.created');
      expect(createdInviteLog).toBeDefined();
      expect(createdInviteLog?.rawInviteToken).toBeUndefined();
    } finally {
      await close();
    }
  });

  it('includes the raw invite token only when local-dev logging is explicitly enabled', async () => {
    const { deps, close } = await buildTestApp();
    const logEntries: Array<Record<string, unknown>> = [];

    try {
      await runTenantBootstrap({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        outboxRepo: deps.outboxRepo,
        outboxEncryption: deps.outboxEncryption,
        options: {
          tenantKey: 'bootstrap-local',
          tenantName: 'Bootstrap Local',
          adminEmail: 'local-admin@example.com',
          inviteTtlHours: 24,
          emitRawInviteTokenToLogs: true,
          logInfo: (entry) => {
            logEntries.push(entry);
          },
        },
      });

      const createdInviteLog = logEntries.find((entry) => entry.msg === 'seed.invite.created');
      expect(createdInviteLog).toBeDefined();
      expect(typeof createdInviteLog?.rawInviteToken).toBe('string');
      expect(String(createdInviteLog?.rawInviteToken)).not.toHaveLength(0);
    } finally {
      await close();
    }
  });
});
