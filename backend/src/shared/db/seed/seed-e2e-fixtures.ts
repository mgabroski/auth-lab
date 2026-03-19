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

  // Seed the third admin persona used exclusively by the MFA recovery Playwright test.
  await seedE2eRecoveryAdminPersona({ db, passwordHasher, tenant });

  // Seed the fourth persona used exclusively by the password reset Playwright test.
  await seedE2eResetMemberPersona({ db, passwordHasher, tenant });
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

// ── Third E2E admin persona: recovery-admin ──────────────────────────────────
//
// WHY a dedicated persona for the MFA recovery Playwright test (test 18):
// - The primary e2e-admin (e2e-admin@example.com) goes through MFA setup in
//   test 16 (mfa full loop). After that test runs, the persona has a verified
//   MFA secret, so the next login returns MFA_REQUIRED, not MFA_SETUP_REQUIRED.
// - The invite-admin (e2e-invite-admin@example.com) also configures MFA in
//   test 17 (invite acceptance journey). Same problem.
// - Test 18 needs a persona that ALWAYS starts with no MFA so it goes through
//   MFA_SETUP_REQUIRED → /auth/mfa/setup, where it can read recovery codes off
//   the page and then prove the recovery code flow end-to-end.
// - This persona is never used by any other test, so its MFA state is never
//   touched mid-run. The seed clears it on every run to guarantee a clean start.
//
// PERSONAS CREATED:
//   goodwill-open / e2e-recovery-admin@example.com
//     - ADMIN role, ACTIVE status, email_verified: true
//     - Password: Password123!
//     - No MFA rows → login always returns MFA_SETUP_REQUIRED

const E2E_RECOVERY_ADMIN_EMAIL = 'e2e-recovery-admin@example.com';
const E2E_RECOVERY_ADMIN_NAME = 'E2E Recovery Admin';

async function seedE2eRecoveryAdminPersona(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  tenant: { id: string; key: string };
}): Promise<void> {
  const { db, passwordHasher, tenant } = opts;
  const flow = 'seed.e2e.recovery_admin';
  const email = E2E_RECOVERY_ADMIN_EMAIL.toLowerCase();

  // ── Ensure user row ──────────────────────────────────────────────────────
  let user = await db
    .selectFrom('users')
    .select(['id', 'email', 'name', 'email_verified'])
    .where('email', '=', email)
    .executeTakeFirst();

  if (!user) {
    user = await db
      .insertInto('users')
      .values({ email, name: E2E_RECOVERY_ADMIN_NAME, email_verified: true })
      .returning(['id', 'email', 'name', 'email_verified'])
      .executeTakeFirstOrThrow();
    logger.info('seed.e2e.recovery_admin.user.created', { flow, email, userId: user.id });
  } else {
    if (!user.email_verified) {
      await db
        .updateTable('users')
        .set({ email_verified: true })
        .where('id', '=', user.id)
        .execute();
    }
    logger.info('seed.e2e.recovery_admin.user.exists', { flow, email, userId: user.id });
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
    logger.info('seed.e2e.recovery_admin.password_identity.created', {
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
    logger.info('seed.e2e.recovery_admin.membership.created', { flow, email, userId: user.id });
  } else if (existing.role !== 'ADMIN' || existing.status !== 'ACTIVE') {
    await db
      .updateTable('memberships')
      .set({ role: 'ADMIN', status: 'ACTIVE', suspended_at: null })
      .where('id', '=', existing.id)
      .execute();
    logger.info('seed.e2e.recovery_admin.membership.patched', { flow, email, userId: user.id });
  }

  // ── Clear ALL MFA state ───────────────────────────────────────────────────
  // WHY: test 18 goes through MFA setup on every run. Without clearing,
  // a previous run's mfa_secrets row would cause login to return MFA_REQUIRED
  // instead of MFA_SETUP_REQUIRED, and the test would land on /auth/mfa/verify
  // instead of /auth/mfa/setup, breaking the recovery-code read step.
  await db.deleteFrom('mfa_recovery_codes').where('user_id', '=', user.id).execute();
  await db.deleteFrom('mfa_secrets').where('user_id', '=', user.id).executeTakeFirst();

  logger.info('seed.e2e.recovery_admin.done', {
    flow,
    email,
    tenantKey: tenant.key,
    message: 'E2E recovery-admin persona ready: ADMIN, ACTIVE, email_verified, no MFA',
  });
}

// ── Fourth E2E persona: reset-member ─────────────────────────────────────────
//
// WHY a dedicated persona for the password reset Playwright test (test 19):
// - Test 19 changes the member's password as part of the reset flow proof.
// - Using the shared member@example.com persona broke tests 1, 2, 10, 13, 14
//   on the same run because those tests all depend on MEMBER_PASSWORD being
//   correct. Any failure in test 19's restore step poisons the whole suite.
// - A dedicated persona that only test 19 uses means no other test cares what
//   happens to its password. No restore step needed. No cross-test contamination.
// - This is a MEMBER (not ADMIN) with public signup and password auth, which
//   is exactly what the password reset flow requires.
//
// PERSONAS CREATED:
//   goodwill-open / e2e-reset-member@example.com
//     - MEMBER role, ACTIVE status, email_verified: true
//     - Password: Password123!

const E2E_RESET_MEMBER_EMAIL = 'e2e-reset-member@example.com';
const E2E_RESET_MEMBER_NAME = 'E2E Reset Member';

async function seedE2eResetMemberPersona(opts: {
  db: DbExecutor;
  passwordHasher: PasswordHasher;
  tenant: { id: string; key: string };
}): Promise<void> {
  const { db, passwordHasher, tenant } = opts;
  const flow = 'seed.e2e.reset_member';
  const email = E2E_RESET_MEMBER_EMAIL.toLowerCase();

  // ── Ensure user row ──────────────────────────────────────────────────────
  let user = await db
    .selectFrom('users')
    .select(['id', 'email', 'name', 'email_verified'])
    .where('email', '=', email)
    .executeTakeFirst();

  if (!user) {
    user = await db
      .insertInto('users')
      .values({ email, name: E2E_RESET_MEMBER_NAME, email_verified: true })
      .returning(['id', 'email', 'name', 'email_verified'])
      .executeTakeFirstOrThrow();
    logger.info('seed.e2e.reset_member.user.created', { flow, email, userId: user.id });
  } else {
    if (!user.email_verified) {
      await db
        .updateTable('users')
        .set({ email_verified: true })
        .where('id', '=', user.id)
        .execute();
    }
    logger.info('seed.e2e.reset_member.user.exists', { flow, email, userId: user.id });
  }

  // ── Always reset password back to Password123! ───────────────────────────
  // WHY: Test 19 changes this password as part of the reset flow. The seed
  // restores it on every run so the test always starts from a known state.
  const passwordHash = await passwordHasher.hash(E2E_ADMIN_PASSWORD);
  const existingIdentity = await db
    .selectFrom('auth_identities')
    .select(['id'])
    .where('user_id', '=', user.id)
    .where('provider', '=', 'password')
    .executeTakeFirst();

  if (!existingIdentity) {
    await db
      .insertInto('auth_identities')
      .values({
        user_id: user.id,
        provider: 'password',
        provider_subject: null,
        password_hash: passwordHash,
      })
      .executeTakeFirstOrThrow();
    logger.info('seed.e2e.reset_member.password_identity.created', {
      flow,
      email,
      userId: user.id,
    });
  } else {
    // Always overwrite — test 19 changes the password, seed restores it.
    await db
      .updateTable('auth_identities')
      .set({ password_hash: passwordHash })
      .where('id', '=', existingIdentity.id)
      .execute();
    logger.info('seed.e2e.reset_member.password_identity.reset', { flow, email, userId: user.id });
  }

  // ── Ensure MEMBER ACTIVE membership ─────────────────────────────────────
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
        role: 'MEMBER',
        status: 'ACTIVE',
        invited_at: now,
        accepted_at: now,
        suspended_at: null,
      })
      .executeTakeFirstOrThrow();
    logger.info('seed.e2e.reset_member.membership.created', { flow, email, userId: user.id });
  } else if (existing.status !== 'ACTIVE') {
    await db
      .updateTable('memberships')
      .set({ status: 'ACTIVE', suspended_at: null })
      .where('id', '=', existing.id)
      .execute();
    logger.info('seed.e2e.reset_member.membership.patched', { flow, email, userId: user.id });
  }

  logger.info('seed.e2e.reset_member.done', {
    flow,
    email,
    tenantKey: tenant.key,
    message:
      'E2E reset-member persona ready: MEMBER, ACTIVE, email_verified, password restored to Password123!',
  });
}
