import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';

import { buildTestApp } from '../helpers/build-test-app';
import type { DbExecutor } from '../../src/shared/db/db';
import type { TokenHasher } from '../../src/shared/security/token-hasher';
import type { InviteRole } from '../../src/modules/invites/invite.types';

/**
 * WHY:
 * - E2E tests must verify real side-effects in Postgres:
 *   - invite accepted
 *   - audit event appended
 *
 * RULES:
 * - No debug endpoints.
 * - No mocking for auth/provisioning correctness.
 * - Create isolated tenant/invite per test to avoid collisions.
 * - No `any`: keep tests as strict as prod code.
 */

const AcceptInviteResponseSchema = z.object({
  status: z.literal('ACCEPTED'),
  nextAction: z.enum(['SET_PASSWORD', 'SIGN_IN', 'MFA_SETUP_REQUIRED']),
});

type AcceptInviteResponse = z.infer<typeof AcceptInviteResponseSchema>;

const AuditInviteAcceptedMetaSchema = z.object({
  inviteId: z.string().uuid(),
  email: z.string().email(),
  role: z.enum(['ADMIN', 'MEMBER']),
});

type AuditInviteAcceptedMeta = z.infer<typeof AuditInviteAcceptedMetaSchema>;

async function createTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  tenantName: string;
  isActive?: boolean;
}): Promise<{ id: string; key: string }> {
  const row = await opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: opts.tenantName,
      is_active: opts.isActive ?? true,
      public_signup_enabled: false,
      member_mfa_required: false,
      allowed_email_domains: sql`'[]'::jsonb`,
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();

  return { id: row.id, key: row.key };
}

async function createInvite(opts: {
  db: DbExecutor;
  tokenHasher: TokenHasher;
  tenantId: string;
  email: string;
  role: InviteRole;
  status?: 'PENDING' | 'ACCEPTED' | 'CANCELLED' | 'EXPIRED';
  expiresAt: Date;
  tokenRaw: string;
}): Promise<{ id: string; tenantId: string; status: string; tokenHash: string }> {
  const tokenHash = opts.tokenHasher.hash(opts.tokenRaw);

  const row = await opts.db
    .insertInto('invites')
    .values({
      tenant_id: opts.tenantId,
      email: opts.email.toLowerCase(),
      role: opts.role,
      status: opts.status ?? 'PENDING',
      token_hash: tokenHash,
      expires_at: opts.expiresAt,
      used_at: null,
      created_by_user_id: null,
    })
    .returning(['id', 'tenant_id', 'status', 'token_hash'])
    .executeTakeFirstOrThrow();

  return {
    id: row.id,
    tenantId: row.tenant_id,
    status: row.status,
    tokenHash: row.token_hash,
  };
}

describe('POST /auth/invites/accept', () => {
  it('accepts a valid pending invite, marks it used, and writes audit event', async () => {
    const { app, deps, close } = await buildTestApp();

    const { db, tokenHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    const tokenRaw = `inv_${randomUUID()}_${randomUUID()}`;
    const email = `user-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({
        db,
        tenantKey,
        tenantName: `Tenant ${tenantKey}`,
        isActive: true,
      });

      const invite = await createInvite({
        db,
        tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        tokenRaw,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/invites/accept',
        headers: { host },
        payload: { token: tokenRaw },
      });

      expect(res.statusCode).toBe(200);

      const parsed: AcceptInviteResponse = AcceptInviteResponseSchema.parse(res.json());
      expect(parsed.status).toBe('ACCEPTED');

      const inviteRow = await db
        .selectFrom('invites')
        .select(['id', 'status', 'used_at', 'tenant_id'])
        .where('id', '=', invite.id)
        .executeTakeFirstOrThrow();

      expect(inviteRow.tenant_id).toBe(tenant.id);
      expect(inviteRow.used_at).not.toBeNull();
      expect(inviteRow.status).toBe('ACCEPTED');

      const auditRows = await db
        .selectFrom('audit_events')
        .select(['id', 'action', 'tenant_id', 'metadata'])
        .where('tenant_id', '=', tenant.id)
        .where('action', '=', 'invite.accepted')
        .execute();

      expect(auditRows).toHaveLength(1);
      expect(auditRows[0].tenant_id).toBe(tenant.id);

      const meta: AuditInviteAcceptedMeta = AuditInviteAcceptedMetaSchema.parse(
        auditRows[0].metadata,
      );

      expect(meta.inviteId).toBe(invite.id);
      expect(meta.email).toBe(email.toLowerCase());
      expect(meta.role).toBe('MEMBER');
    } finally {
      await close();
    }
  });

  it('rejects an expired invite (conflict) and does not write audit event', async () => {
    const { app, deps, close } = await buildTestApp();

    const { db, tokenHasher } = deps;

    const tenantKey = `t-${randomUUID().slice(0, 10)}`;
    const host = `${tenantKey}.localhost:3000`;

    const tokenRaw = `inv_${randomUUID()}_${randomUUID()}`;
    const email = `user-${randomUUID().slice(0, 8)}@example.com`;

    try {
      const tenant = await createTenant({
        db,
        tenantKey,
        tenantName: `Tenant ${tenantKey}`,
        isActive: true,
      });

      const invite = await createInvite({
        db,
        tokenHasher,
        tenantId: tenant.id,
        email,
        role: 'MEMBER',
        expiresAt: new Date(Date.now() - 60 * 1000),
        tokenRaw,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/auth/invites/accept',
        headers: { host },
        payload: { token: tokenRaw },
      });

      expect(res.statusCode).toBe(409);

      const inviteRow = await db
        .selectFrom('invites')
        .select(['id', 'status', 'used_at'])
        .where('id', '=', invite.id)
        .executeTakeFirstOrThrow();

      expect(inviteRow.used_at).toBeNull();
      expect(inviteRow.status).toBe('PENDING');

      const auditRows = await db
        .selectFrom('audit_events')
        .select(['id'])
        .where('tenant_id', '=', tenant.id)
        .where('action', '=', 'invite.accepted')
        .execute();

      expect(auditRows).toHaveLength(0);
    } finally {
      await close();
    }
  });
});
