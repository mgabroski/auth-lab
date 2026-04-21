/**
 * backend/src/shared/db/seed/bootstrap-tenant.ts
 *
 * WHY:
 * - Owns the shared tenant-bootstrap behavior used by both local dev seeding
 *   and operator-driven bootstrap in QA/staging/production-like environments.
 * - Keeps the bootstrap invite contract consistent across environments while
 *   still allowing local-only raw-token logging convenience.
 *
 * RULES:
 * - Bootstrap creates/ensures exactly one target tenant, the foundational
 *   native Settings rows for that tenant, and one pending ADMIN invite for the
 *   requested email. It must not create extra convenience personas or extra
 *   tenants.
 * - Outbox-backed invite delivery remains the source of truth when
 *   outboxRepo/outboxEncryption are provided.
 * - Raw invite token logging is opt-in and allowed only for local developer
 *   convenience. Operator/bootstrap flows must call this with
 *   emitRawInviteTokenToLogs=false.
 */

import { randomUUID } from 'node:crypto';

import type { DbExecutor } from '../db';
import type { TokenHasher } from '../../security/token-hasher';
import type { OutboxRepo } from '../../outbox/outbox.repo';
import type { OutboxEncryption } from '../../outbox/outbox-encryption';
import { logger } from '../../logger/logger';
import { SettingsFoundationRepo } from '../../../modules/settings/dal/settings-foundation.repo';
import { SETTINGS_REASON_CODES } from '../../../modules/settings/settings.types';

export type BootstrapTenantOptions = {
  tenantKey: string;
  tenantName: string;
  adminEmail: string;
  inviteTtlHours: number;
  emitRawInviteTokenToLogs?: boolean;
  logInfo?: (entry: Record<string, unknown>) => void;
};

type TenantBootstrapShape = {
  key: string;
  name: string;
};

function addHours(date: Date, hours: number): Date {
  return new Date(date.getTime() + hours * 60 * 60 * 1000);
}

async function ensureBootstrapTenant(
  db: DbExecutor,
  tenant: TenantBootstrapShape,
  logInfo: (entry: Record<string, unknown>) => void,
): Promise<{ id: string; key: string }> {
  const existing = await db
    .selectFrom('tenants')
    .select(['id', 'key', 'name'])
    .where('key', '=', tenant.key)
    .executeTakeFirst();

  if (existing) {
    logInfo({
      flow: 'seed.bootstrap',
      msg: 'seed.tenant.exists',
      tenantKey: tenant.key,
      tenantId: existing.id,
      tenantName: existing.name,
      publicSignupEnabled: false,
    });

    return { id: existing.id, key: existing.key };
  }

  const inserted = await db
    .insertInto('tenants')
    .values({
      key: tenant.key,
      name: tenant.name,
      is_active: true,
      public_signup_enabled: false,
      member_mfa_required: false,
      allowed_sso: ['google', 'microsoft'],
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();

  logInfo({
    flow: 'seed.bootstrap',
    msg: 'seed.tenant.created',
    tenantKey: tenant.key,
    tenantId: inserted.id,
    tenantName: tenant.name,
    publicSignupEnabled: false,
  });

  return inserted;
}

async function ensureBootstrapAdminInvite(opts: {
  db: DbExecutor;
  tokenHasher: TokenHasher;
  tenantId: string;
  tenantKey: string;
  adminEmail: string;
  inviteTtlHours: number;
  outboxRepo?: OutboxRepo;
  outboxEncryption?: OutboxEncryption;
  emitRawInviteTokenToLogs: boolean;
  logInfo: (entry: Record<string, unknown>) => void;
}): Promise<void> {
  const {
    db,
    tokenHasher,
    tenantId,
    tenantKey,
    adminEmail,
    inviteTtlHours,
    outboxRepo,
    outboxEncryption,
    emitRawInviteTokenToLogs,
    logInfo,
  } = opts;
  const flow = 'seed.bootstrap';
  const email = adminEmail.toLowerCase();

  const existingInvite = await db
    .selectFrom('invites')
    .select(['id', 'email', 'status', 'expires_at', 'used_at'])
    .where('tenant_id', '=', tenantId)
    .where('email', '=', email)
    .where('role', '=', 'ADMIN')
    .executeTakeFirst();

  if (existingInvite) {
    logInfo({
      flow,
      msg: 'seed.invite.exists',
      tenantKey,
      tenantId,
      inviteId: existingInvite.id,
      email: existingInvite.email,
      status: existingInvite.status,
      expiresAt: existingInvite.expires_at,
      usedAt: existingInvite.used_at,
    });
    return;
  }

  const rawToken = randomUUID().replace(/-/g, '');
  const tokenHash = tokenHasher.hash(rawToken);
  const expiresAt = addHours(new Date(), inviteTtlHours);

  const created = await db.transaction().execute(async (trx) => {
    const inserted = await trx
      .insertInto('invites')
      .values({
        tenant_id: tenantId,
        email,
        role: 'ADMIN',
        status: 'PENDING',
        token_hash: tokenHash,
        expires_at: expiresAt,
        created_by_user_id: null,
        used_at: null,
      })
      .returning(['id'])
      .executeTakeFirstOrThrow();

    if (outboxRepo && outboxEncryption) {
      await outboxRepo.enqueueWithinTx(trx, {
        type: 'invite.created',
        payload: outboxEncryption.encryptPayload({
          token: rawToken,
          toEmail: email,
          tenantKey,
          inviteId: inserted.id,
          role: 'ADMIN',
        }),
        idempotencyKey: `seed.invite.created:${tenantId}:${email}`,
      });
    }

    return inserted;
  });

  logInfo({
    flow,
    msg: 'seed.invite.created',
    tenantKey,
    tenantId,
    inviteId: created.id,
    email,
    role: 'ADMIN',
    status: 'PENDING',
    expiresAt,
    outboxQueued: Boolean(outboxRepo && outboxEncryption),
    ...(emitRawInviteTokenToLogs ? { rawInviteToken: rawToken } : {}),
  });
}

export async function runTenantBootstrap(opts: {
  db: DbExecutor;
  tokenHasher: TokenHasher;
  outboxRepo?: OutboxRepo;
  outboxEncryption?: OutboxEncryption;
  options: BootstrapTenantOptions;
}): Promise<void> {
  const { db, tokenHasher, outboxRepo, outboxEncryption, options } = opts;

  const logInfo = options.logInfo ?? ((entry: Record<string, unknown>) => logger.info(entry));

  const tenant = await ensureBootstrapTenant(
    db,
    {
      key: options.tenantKey,
      name: options.tenantName,
    },
    logInfo,
  );

  await new SettingsFoundationRepo(db).ensureFoundationRows({
    tenantId: tenant.id,
    appliedCpRevision: 0,
    creationReasonCode: SETTINGS_REASON_CODES.TENANT_BOOTSTRAP_FOUNDATION,
  });

  await ensureBootstrapAdminInvite({
    db,
    tokenHasher,
    tenantId: tenant.id,
    tenantKey: tenant.key,
    adminEmail: options.adminEmail,
    inviteTtlHours: options.inviteTtlHours,
    outboxRepo,
    outboxEncryption,
    emitRawInviteTokenToLogs: options.emitRawInviteTokenToLogs ?? false,
    logInfo,
  });
}
