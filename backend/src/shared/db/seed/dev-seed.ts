/**
 * backend/src/shared/db/seed/dev-seed.ts
 *
 * DEV-ONLY canonical auth seed bootstrap.
 *
 * Creates or ensures:
 * - a canonical admin-bootstrap tenant with public signup disabled
 * - an initial admin invite for onboarding proof
 * - a canonical public-signup-enabled tenant
 * - a canonical member login persona with password auth
 *
 * Idempotent: safe to run on every start.
 *
 * IMPORTANT:
 * - Stores only token_hash in DB
 * - Prints raw invite token ONLY to logs (local dev convenience)
 * - Never runs in production
 */

import type { DbExecutor } from '../db';
import type { TokenHasher } from '../../security/token-hasher';
import type { PasswordHasher } from '../../security/password-hasher';
import { logger } from '../../logger/logger';
import type { OutboxRepo } from '../../outbox/outbox.repo';
import type { OutboxEncryption } from '../../outbox/outbox-encryption';
import { runTenantBootstrap } from './bootstrap-tenant';

type DevSeedOptions = {
  tenantKey: string;
  tenantName: string;
  adminEmail: string;
  inviteTtlHours: number;
};

type TenantSeedShape = {
  key: string;
  name: string;
  publicSignupEnabled: boolean;
  memberMfaRequired: boolean;
};

type MemberSeedShape = {
  tenantId: string;
  tenantKey: string;
  email: string;
  name: string;
  password: string;
};

async function ensureTenant(
  db: DbExecutor,
  tenant: TenantSeedShape,
): Promise<{ id: string; key: string }> {
  const existing = await db
    .selectFrom('tenants')
    .select(['id', 'key', 'name'])
    .where('key', '=', tenant.key)
    .executeTakeFirst();

  if (existing) {
    logger.info('seed.tenant.exists', {
      flow: 'seed.dev',
      tenantKey: tenant.key,
      tenantId: existing.id,
      tenantName: existing.name,
      publicSignupEnabled: tenant.publicSignupEnabled,
    });

    return { id: existing.id, key: existing.key };
  }

  const inserted = await db
    .insertInto('tenants')
    .values({
      key: tenant.key,
      name: tenant.name,
      is_active: true,
      public_signup_enabled: tenant.publicSignupEnabled,
      member_mfa_required: tenant.memberMfaRequired,
      allowed_sso: ['google', 'microsoft'],
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();

  logger.info('seed.tenant.created', {
    flow: 'seed.dev',
    tenantKey: tenant.key,
    tenantId: inserted.id,
    tenantName: tenant.name,
    publicSignupEnabled: tenant.publicSignupEnabled,
  });

  return inserted;
}

async function ensureMemberPersona(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  member: MemberSeedShape;
}): Promise<void> {
  const { db, passwordHasher, member } = opts;
  const flow = 'seed.dev';
  const email = member.email.toLowerCase();

  let user = await db
    .selectFrom('users')
    .select(['id', 'email', 'name', 'email_verified'])
    .where('email', '=', email)
    .executeTakeFirst();

  if (!user) {
    user = await db
      .insertInto('users')
      .values({
        email,
        name: member.name,
        email_verified: true,
      })
      .returning(['id', 'email', 'name', 'email_verified'])
      .executeTakeFirstOrThrow();

    logger.info('seed.user.created', {
      flow,
      tenantKey: member.tenantKey,
      userId: user.id,
      email,
      name: member.name,
    });
  } else {
    logger.info('seed.user.exists', {
      flow,
      tenantKey: member.tenantKey,
      userId: user.id,
      email,
      name: user.name,
      emailVerified: user.email_verified,
    });
  }

  const identity = await db
    .selectFrom('auth_identities')
    .select(['id'])
    .where('user_id', '=', user.id)
    .where('provider', '=', 'password')
    .executeTakeFirst();

  if (!identity) {
    const passwordHash = await passwordHasher.hash(member.password);

    await db
      .insertInto('auth_identities')
      .values({
        user_id: user.id,
        provider: 'password',
        provider_subject: null,
        password_hash: passwordHash,
      })
      .executeTakeFirstOrThrow();

    logger.info('seed.password_identity.created', {
      flow,
      tenantKey: member.tenantKey,
      userId: user.id,
      email,
    });
  } else {
    logger.info('seed.password_identity.exists', {
      flow,
      tenantKey: member.tenantKey,
      userId: user.id,
      email,
    });
  }

  const existingMembership = await db
    .selectFrom('memberships')
    .select(['id', 'status', 'role'])
    .where('tenant_id', '=', member.tenantId)
    .where('user_id', '=', user.id)
    .executeTakeFirst();

  if (!existingMembership) {
    const acceptedAt = new Date();

    const createdMembership = await db
      .insertInto('memberships')
      .values({
        tenant_id: member.tenantId,
        user_id: user.id,
        role: 'MEMBER',
        status: 'ACTIVE',
        invited_at: acceptedAt,
        accepted_at: acceptedAt,
        suspended_at: null,
      })
      .returning(['id'])
      .executeTakeFirstOrThrow();

    logger.info('seed.membership.created', {
      flow,
      tenantKey: member.tenantKey,
      membershipId: createdMembership.id,
      userId: user.id,
      email,
      role: 'MEMBER',
      status: 'ACTIVE',
    });

    return;
  }

  logger.info('seed.membership.exists', {
    flow,
    tenantKey: member.tenantKey,
    membershipId: existingMembership.id,
    userId: user.id,
    email,
    role: existingMembership.role,
    status: existingMembership.status,
  });
}

export async function runDevSeed(opts: {
  db: DbExecutor;
  tokenHasher: TokenHasher;
  passwordHasher: PasswordHasher;
  outboxRepo?: OutboxRepo;
  outboxEncryption?: OutboxEncryption;
  options: DevSeedOptions;
}): Promise<void> {
  const { db, tokenHasher, passwordHasher, outboxRepo, outboxEncryption, options } = opts;

  await runTenantBootstrap({
    db,
    tokenHasher,
    outboxRepo,
    outboxEncryption,
    options: {
      tenantKey: options.tenantKey,
      tenantName: options.tenantName,
      adminEmail: options.adminEmail,
      inviteTtlHours: options.inviteTtlHours,
      emitRawInviteTokenToLogs: true,
      logInfo: (entry) => logger.info(entry),
    },
  });

  const publicSignupTenant = await ensureTenant(db, {
    key: 'goodwill-open',
    name: 'GoodWill Open Signup',
    publicSignupEnabled: true,
    memberMfaRequired: false,
  });

  await ensureMemberPersona({
    db,
    passwordHasher,
    member: {
      tenantId: publicSignupTenant.id,
      tenantKey: publicSignupTenant.key,
      email: 'member@example.com',
      name: 'Seeded Member',
      password: 'Password123!',
    },
  });
}
