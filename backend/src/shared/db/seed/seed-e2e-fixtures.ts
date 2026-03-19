/**
 * backend/src/shared/db/seed/seed-e2e-fixtures.ts
 *
 * WHY:
 * - Creates real-stack E2E test personas that cannot be satisfied by the dev
 *   seed alone.
 * - The dev seed creates a MEMBER in goodwill-open.  E2E Phase 8 smoke tests
 *   additionally require an ADMIN persona in goodwill-open with no MFA
 *   configured, so the backend returns MFA_SETUP_REQUIRED on login and the
 *   Playwright test can prove the frontend continuation routing is wired
 *   correctly against the real stack.
 * - Idempotent: safe to run on every CI run or local reseed without accumulating
 *   duplicate rows.
 *
 * RULES:
 * - Never run in production (guarded at call site in run-seed-e2e-fixtures.ts).
 * - Does NOT log raw tokens or secrets — there are none to log here.
 * - Depends on the dev seed having already created the goodwill-open tenant.
 *   In CI the backend starts with SEED_ON_START=true, so the dev seed always
 *   runs before this fixture seed is invoked.
 * - Only creates the minimum required personas — do not add extras here.
 *
 * PERSONAS CREATED:
 *   goodwill-open / e2e-admin@example.com
 *     - ADMIN role, ACTIVE status, email_verified: true
 *     - Password: Password123!
 *     - No MFA rows → login will return MFA_SETUP_REQUIRED
 *     - Used by: admin-login-MFA-continuation smoke test
 */

import type { DbExecutor } from '../db';
import type { PasswordHasher } from '../../security/password-hasher';
import { logger } from '../../logger/logger';

const E2E_ADMIN_EMAIL = 'e2e-admin@example.com';
const E2E_ADMIN_NAME = 'E2E Admin';
const E2E_ADMIN_PASSWORD = 'Password123!';
const E2E_ADMIN_TENANT_KEY = 'goodwill-open';

export async function seedE2eFixtures(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
}): Promise<void> {
  const { db, passwordHasher } = opts;
  const flow = 'seed.e2e';

  // ── Locate the goodwill-open tenant ─────────────────────────────────────
  const tenant = await db
    .selectFrom('tenants')
    .select(['id', 'key', 'name'])
    .where('key', '=', E2E_ADMIN_TENANT_KEY)
    .executeTakeFirst();

  if (!tenant) {
    throw new Error(
      `[seed.e2e] Prerequisite failed: tenant '${E2E_ADMIN_TENANT_KEY}' not found. ` +
        'The dev seed must run before the E2E fixture seed.',
    );
  }

  logger.info('seed.e2e.tenant.found', { flow, tenantKey: tenant.key, tenantId: tenant.id });

  // ── Ensure user row ──────────────────────────────────────────────────────

  const email = E2E_ADMIN_EMAIL.toLowerCase();

  let user = await db
    .selectFrom('users')
    .select(['id', 'email', 'name', 'email_verified'])
    .where('email', '=', email)
    .executeTakeFirst();

  if (!user) {
    user = await db
      .insertInto('users')
      .values({ email, name: E2E_ADMIN_NAME, email_verified: true })
      .returning(['id', 'email', 'name', 'email_verified'])
      .executeTakeFirstOrThrow();

    logger.info('seed.e2e.user.created', { flow, email, userId: user.id });
  } else {
    if (!user.email_verified) {
      await db
        .updateTable('users')
        .set({ email_verified: true })
        .where('id', '=', user.id)
        .execute();
      logger.info('seed.e2e.user.email_verified.patched', { flow, email, userId: user.id });
    } else {
      logger.info('seed.e2e.user.exists', { flow, email, userId: user.id });
    }
  }

  // ── Ensure password identity ─────────────────────────────────────────────

  const identity = await db
    .selectFrom('auth_identities')
    .select(['id'])
    .where('user_id', '=', user.id)
    .where('provider', '=', 'password')
    .executeTakeFirst();

  if (!identity) {
    const passwordHash = await passwordHasher.hash(E2E_ADMIN_PASSWORD);
    await db
      .insertInto('auth_identities')
      .values({
        user_id: user.id,
        provider: 'password',
        provider_subject: null,
        password_hash: passwordHash,
      })
      .executeTakeFirstOrThrow();
    logger.info('seed.e2e.password_identity.created', { flow, email, userId: user.id });
  } else {
    logger.info('seed.e2e.password_identity.exists', { flow, email, userId: user.id });
  }

  // ── Ensure ADMIN ACTIVE membership in goodwill-open ──────────────────────

  const existingMembership = await db
    .selectFrom('memberships')
    .select(['id', 'role', 'status'])
    .where('tenant_id', '=', tenant.id)
    .where('user_id', '=', user.id)
    .executeTakeFirst();

  if (!existingMembership) {
    const now = new Date();
    const created = await db
      .insertInto('memberships')
      .values({
        tenant_id: tenant.id,
        user_id: user.id,
        role: 'ADMIN',
        status: 'ACTIVE',
        invited_at: now,
        accepted_at: now,
        suspended_at: null,
      })
      .returning(['id'])
      .executeTakeFirstOrThrow();
    logger.info('seed.e2e.membership.created', {
      flow,
      email,
      userId: user.id,
      membershipId: created.id,
      tenantKey: tenant.key,
      role: 'ADMIN',
      status: 'ACTIVE',
    });
  } else {
    if (existingMembership.role !== 'ADMIN' || existingMembership.status !== 'ACTIVE') {
      await db
        .updateTable('memberships')
        .set({ role: 'ADMIN', status: 'ACTIVE', suspended_at: null })
        .where('id', '=', existingMembership.id)
        .execute();
      logger.info('seed.e2e.membership.patched', {
        flow,
        email,
        userId: user.id,
        membershipId: existingMembership.id,
        tenantKey: tenant.key,
      });
    } else {
      logger.info('seed.e2e.membership.exists', {
        flow,
        email,
        userId: user.id,
        membershipId: existingMembership.id,
        tenantKey: tenant.key,
      });
    }
  }

  // ── Clear ALL MFA state for this persona ─────────────────────────────────
  //
  // WHY both tables must be cleared:
  // - mfa_recovery_codes has REFERENCES users(id) ON DELETE CASCADE.
  //   It does NOT cascade on mfa_secrets deletion.
  // - Orphan recovery code rows from previous runs remain after mfa_secrets
  //   is deleted. The MFA setup flow does not delete old codes before inserting
  //   new ones. Clearing both here keeps the persona in a clean known state.

  await db.deleteFrom('mfa_recovery_codes').where('user_id', '=', user.id).execute();

  const mfaDeleted = await db
    .deleteFrom('mfa_secrets')
    .where('user_id', '=', user.id)
    .executeTakeFirst();

  if (mfaDeleted.numDeletedRows > 0n) {
    logger.info('seed.e2e.mfa_secrets.cleared', {
      flow,
      email,
      userId: user.id,
      rows: Number(mfaDeleted.numDeletedRows),
      reason: 'E2E admin persona must start with no MFA to trigger MFA_SETUP_REQUIRED',
    });
  }

  logger.info('seed.e2e.done', {
    flow,
    email,
    tenantKey: tenant.key,
    message:
      'E2E admin persona is ready: ADMIN, ACTIVE, email_verified, no MFA → login returns MFA_SETUP_REQUIRED',
  });

  // Seed the second admin persona used by the invite-acceptance Playwright test.
  await seedE2eInviteAdminPersona({ db, passwordHasher, tenant });
}

// ── Second E2E admin persona: invite-admin ───────────────────────────────────
//
// WHY a separate persona for the invite-acceptance Playwright test:
// - The primary e2e-admin persona (e2e-admin@example.com) has its MFA state
//   cleared by the seed so it always starts with no MFA. After the MFA-loop
//   Playwright test (test 11) runs, that admin has a configured + verified MFA
//   secret. The invite-acceptance test (test 12) also needs a fresh admin to
//   drive POST /admin/invites — but it must be MFA-verified to call that endpoint.
// - If test 12 reused e2e-admin@example.com, it would encounter MFA_REQUIRED
//   (login continuation, not MFA_SETUP_REQUIRED) and the verify flow differs.
// - A dedicated second persona (e2e-invite-admin@example.com) keeps both tests
//   independent regardless of execution order. It also has its MFA cleared so
//   test 12 always goes through the consistent MFA_SETUP_REQUIRED path.
//
// PERSONAS CREATED:
//   goodwill-open / e2e-invite-admin@example.com
//     - ADMIN role, ACTIVE status, email_verified: true
//     - Password: Password123!
//     - No MFA rows → login will return MFA_SETUP_REQUIRED

const E2E_INVITE_ADMIN_EMAIL = 'e2e-invite-admin@example.com';
const E2E_INVITE_ADMIN_NAME = 'E2E Invite Admin';

async function seedE2eInviteAdminPersona(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  tenant: { id: string; key: string };
}): Promise<void> {
  const { db, passwordHasher, tenant } = opts;
  const flow = 'seed.e2e.invite_admin';
  const email = E2E_INVITE_ADMIN_EMAIL.toLowerCase();

  // ── Ensure user row ──────────────────────────────────────────────────────
  let user = await db
    .selectFrom('users')
    .select(['id', 'email', 'name', 'email_verified'])
    .where('email', '=', email)
    .executeTakeFirst();

  if (!user) {
    user = await db
      .insertInto('users')
      .values({ email, name: E2E_INVITE_ADMIN_NAME, email_verified: true })
      .returning(['id', 'email', 'name', 'email_verified'])
      .executeTakeFirstOrThrow();
    logger.info('seed.e2e.invite_admin.user.created', { flow, email, userId: user.id });
  } else {
    if (!user.email_verified) {
      await db
        .updateTable('users')
        .set({ email_verified: true })
        .where('id', '=', user.id)
        .execute();
    }
    logger.info('seed.e2e.invite_admin.user.exists', { flow, email, userId: user.id });
  }

  // ── Ensure password identity ─────────────────────────────────────────────
  const identity = await db
    .selectFrom('auth_identities')
    .select(['id'])
    .where('user_id', '=', user.id)
    .where('provider', '=', 'password')
    .executeTakeFirst();

  if (!identity) {
    const passwordHash = await passwordHasher.hash(E2E_ADMIN_PASSWORD);
    await db
      .insertInto('auth_identities')
      .values({
        user_id: user.id,
        provider: 'password',
        provider_subject: null,
        password_hash: passwordHash,
      })
      .executeTakeFirstOrThrow();
    logger.info('seed.e2e.invite_admin.password_identity.created', {
      flow,
      email,
      userId: user.id,
    });
  }

  // ── Ensure ADMIN ACTIVE membership ──────────────────────────────────────
  const existing = await db
    .selectFrom('memberships')
    .select(['id', 'role', 'status'])
    .where('tenant_id', '=', tenant.id)
    .where('user_id', '=', user.id)
    .executeTakeFirst();

  if (!existing) {
    const now = new Date();
    await db
      .insertInto('memberships')
      .values({
        tenant_id: tenant.id,
        user_id: user.id,
        role: 'ADMIN',
        status: 'ACTIVE',
        invited_at: now,
        accepted_at: now,
        suspended_at: null,
      })
      .executeTakeFirstOrThrow();
    logger.info('seed.e2e.invite_admin.membership.created', { flow, email, userId: user.id });
  } else if (existing.role !== 'ADMIN' || existing.status !== 'ACTIVE') {
    await db
      .updateTable('memberships')
      .set({ role: 'ADMIN', status: 'ACTIVE', suspended_at: null })
      .where('id', '=', existing.id)
      .execute();
    logger.info('seed.e2e.invite_admin.membership.patched', { flow, email, userId: user.id });
  }

  // ── Clear ALL MFA state (same reason as primary e2e-admin persona) ───────
  await db.deleteFrom('mfa_recovery_codes').where('user_id', '=', user.id).execute();
  await db.deleteFrom('mfa_secrets').where('user_id', '=', user.id).executeTakeFirst();

  logger.info('seed.e2e.invite_admin.done', {
    flow,
    email,
    tenantKey: tenant.key,
    message: 'E2E invite-admin persona ready: ADMIN, ACTIVE, email_verified, no MFA',
  });
}
