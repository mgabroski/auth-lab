/**
 * backend/src/shared/db/seed/dev-seed.ts
 *
 * DEV-ONLY seed bootstrap.
 *
 * Creates:
 * - a tenant (if missing)
 * - an initial admin invite (if missing)
 *
 * Idempotent: safe to run on every start.
 *
 * IMPORTANT:
 * - Stores only token_hash in DB
 * - Prints raw token ONLY to logs (dev convenience)
 *
 * Invite status must match DB CHECK constraint:
 *   PENDING | ACCEPTED | CANCELLED | EXPIRED
 */

import { randomUUID } from 'node:crypto';

import type { DbExecutor } from '../db';
import type { TokenHasher } from '../../security/token-hasher';
import { logger } from '../../logger/logger';

type DevSeedOptions = {
  tenantKey: string;
  tenantName: string;
  adminEmail: string;
  inviteTtlHours: number;
};

function addHours(date: Date, hours: number): Date {
  return new Date(date.getTime() + hours * 60 * 60 * 1000);
}

export async function runDevSeed(opts: {
  db: DbExecutor;
  tokenHasher: TokenHasher;
  options: DevSeedOptions;
}): Promise<void> {
  const { db, tokenHasher, options } = opts;

  const flow = 'seed.dev';

  // 1) Ensure tenant exists
  const existingTenant = await db
    .selectFrom('tenants')
    .select(['id', 'key', 'name'])
    .where('key', '=', options.tenantKey)
    .executeTakeFirst();

  let tenantId: string;

  if (!existingTenant) {
    const inserted = await db
      .insertInto('tenants')
      .values({
        key: options.tenantKey,
        name: options.tenantName,
        is_active: true,

        // sensible defaults for dev
        public_signup_enabled: false,
        member_mfa_required: false,

        // allowed_email_domains has a DB default ('[]'::jsonb) — don't override
      })
      .returning(['id'])
      .executeTakeFirstOrThrow();

    tenantId = inserted.id;

    logger.info('seed.tenant.created', {
      flow,
      tenantKey: options.tenantKey,
      tenantId,
      tenantName: options.tenantName,
    });
  } else {
    tenantId = existingTenant.id;

    logger.info('seed.tenant.exists', {
      flow,
      tenantKey: options.tenantKey,
      tenantId,
      tenantName: existingTenant.name,
    });
  }

  // 2) Ensure initial admin invite exists
  const email = options.adminEmail.toLowerCase();

  const existingInvite = await db
    .selectFrom('invites')
    .select(['id', 'email', 'status', 'expires_at', 'used_at'])
    .where('tenant_id', '=', tenantId)
    .where('email', '=', email)
    .where('role', '=', 'ADMIN')
    .executeTakeFirst();

  if (existingInvite) {
    logger.info('seed.invite.exists', {
      flow,
      tenantKey: options.tenantKey,
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

  const now = new Date();
  const expiresAt = addHours(now, options.inviteTtlHours);

  const created = await db
    .insertInto('invites')
    .values({
      tenant_id: tenantId,
      email,
      role: 'ADMIN',

      // IMPORTANT: must match invites_status_check constraint
      status: 'PENDING',

      token_hash: tokenHash,
      expires_at: expiresAt,
      created_by_user_id: null,
      used_at: null,
    })
    .returning(['id'])
    .executeTakeFirstOrThrow();

  logger.info('seed.invite.created', {
    flow,
    tenantKey: options.tenantKey,
    tenantId,
    inviteId: created.id,
    email,
    role: 'ADMIN',
    status: 'PENDING',
    expiresAt,

    // DEV ONLY (do NOT do this in prod)
    rawInviteToken: rawToken,
  });
}
