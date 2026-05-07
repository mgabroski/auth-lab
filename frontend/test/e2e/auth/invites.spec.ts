/**
 * frontend/test/e2e/auth/invites.spec.ts
 *
 * WHY: Split from the legacy monolithic auth.spec.ts to keep the auth proof layer navigable while preserving the exact real-stack assertions.
 */

import { expect, test } from '@playwright/test';
import { AUTH_E2E } from './auth-test-context';
import * as MAILPIT from '../helpers/mailpit';
import * as MFA from '../helpers/totp';

test.describe('auth smoke: invite acceptance', () => {
  // ── 12. Invite acceptance full browser journey ────────────────────────────
  //
  // WHY this test exists (Phase 8 roadmap closure — audit S1 item):
  // - Invite flows are proven at the backend E2E level (Fastify inject) but not
  //   in a real browser against the full Docker stack including email delivery.
  // - This test proves the end-to-end invite onboarding path: admin creates invite
  //   → real SMTP delivery via Mailpit → browser accepts token → register form
  //   → authenticated session → /app.
  //
  // WHAT IS PROVEN:
  // - POST /admin/invites creates a real invite and enqueues email delivery.
  // - The outbox worker delivers the email to Mailpit via real SMTP.
  // - The invite link is shaped correctly (tenant-scoped, contains token).
  // - POST /auth/invites/accept returns nextAction: SET_PASSWORD.
  // - POST /auth/register with the token succeeds with 201 and creates a real session.
  // - MEMBER role + no MFA → nextAction: NONE → frontend routes to /app.
  //
  // WHY this test uses a SECOND admin persona (e2e-invite-admin@example.com):
  // - Test 11 configures MFA for e2e-admin@example.com. After test 11, that admin
  //   has MFA_REQUIRED (not MFA_SETUP_REQUIRED) on the next login. Reusing the
  //   same persona would require handling a different continuation branch.
  // - e2e-invite-admin@example.com is seeded with no MFA (same as the primary admin
  //   before test 11 runs), giving this test a fully independent setup path.
  //   See seed-e2e-fixtures.ts for the second persona's seeding logic.

  test('invite acceptance journey: admin creates invite → email → accept → register → session → /app', async ({
    page,
  }) => {
    // WHY 120s: this test does more sequential work than any other test —
    // MFA setup, invite creation, email delivery wait (up to 30s outbox poll),
    // fresh context navigation, and registration. The global 60s is too tight.
    test.setTimeout(120_000);
    const E2E_INVITE_ADMIN_EMAIL = 'e2e-invite-admin@example.com';
    const inviteRecipientEmail = `e2e-invite-recipient-${Date.now()}@example.com`;

    await MAILPIT.purgeMailpit();

    // ── A. Establish a MFA-verified admin session ────────────────────────────
    // The invite-admin persona starts with no MFA → goes through MFA_SETUP_REQUIRED.

    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(E2E_INVITE_ADMIN_EMAIL);
    await page.getByLabel('Password').fill(AUTH_E2E.E2E_ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/auth/mfa/setup`);

    const secretInput = page.getByLabel('Authenticator secret');
    await expect(secretInput).toBeVisible({ timeout: 15_000 });
    const base32Secret = await secretInput.inputValue();

    const setupCode = MFA.generateTotp(base32Secret);
    await page.getByLabel('6-digit code').fill(setupCode);
    await page.getByRole('button', { name: 'Finish MFA setup' }).click();

    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/admin`, { timeout: 15_000 });

    // ── B. Create the invite via POST /api/admin/invites ─────────────────────
    // page.request shares the authenticated session cookie established above.

    const createRes = await page.request.post(`${AUTH_E2E.OPEN_ORIGIN}/api/admin/invites`, {
      data: { email: inviteRecipientEmail, role: 'MEMBER' },
    });
    expect(
      createRes.status(),
      `POST /admin/invites must return 201 (got ${createRes.status()})`,
    ).toBe(201);

    // ── C. Wait for invite email in Mailpit ──────────────────────────────────
    // The outbox worker delivers this asynchronously via real SMTP.

    const message = await MAILPIT.waitForEmailToRecipient(inviteRecipientEmail);
    expect(message.Subject, 'Invite email subject must contain "invite"').toMatch(/invite/i);

    // ── D. Extract invite link ────────────────────────────────────────────────
    const inviteLink = MAILPIT.extractLinkFromText(message.Text, '/accept-invite?token=');
    expect(inviteLink, 'Invite link must be on the open tenant host').toContain(
      `${AUTH_E2E.OPEN_TENANT}.lvh.me`,
    );

    // ── E. Navigate to the invite link as a new (unauthenticated) user ───────
    // Open a fresh browser context so the admin session cookie does not carry over.

    const inviteBrowser = page.context().browser();
    if (!inviteBrowser) throw new Error('Could not get browser instance from page context');

    const freshContext = await inviteBrowser.newContext();
    const freshPage = await freshContext.newPage();

    try {
      await freshPage.goto(inviteLink);

      // accept-invite-flow auto-submits POST /auth/invites/accept on mount.
      // nextAction: SET_PASSWORD → frontend redirects to /auth/register?token=...
      await expect(freshPage).toHaveURL(/\/auth\/register/, { timeout: 15_000 });

      // ── F. Fill and submit the register form ───────────────────────────────
      await freshPage.getByLabel('Full name').fill('Invited Browser User');
      await expect(freshPage.getByLabel('Email')).toHaveValue(inviteRecipientEmail);
      await freshPage.getByLabel('Password').fill('Password123!');

      const registerResponsePromise = freshPage.waitForResponse(
        (response) =>
          response.url() === `${AUTH_E2E.OPEN_ORIGIN}/api/auth/register` &&
          response.request().method() === 'POST',
      );

      await freshPage.getByRole('button', { name: 'Set password and continue' }).click();

      const registerResponse = await registerResponsePromise;
      expect(
        registerResponse.status(),
        `POST /auth/register must return 201 (got ${registerResponse.status()})`,
      ).toBe(201);

      // ── G. Verify landing on /app (MEMBER, no MFA required) ───────────────
      await expect(freshPage).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/app`, { timeout: 15_000 });
      await expect(freshPage.getByRole('heading', { name: 'Member app' })).toBeVisible();
      await expect(freshPage.getByText('Authenticated handoff complete')).toBeVisible();

      // Confirm the session is authenticated as the new member
      const me = await freshPage.request.get(`${AUTH_E2E.OPEN_ORIGIN}/api/auth/me`);
      expect(me.status(), '/api/auth/me must be 200 after invite registration').toBe(200);

      const meBody = (await me.json()) as {
        user: { email: string };
        membership: { role: string };
        session: { mfaVerified: boolean };
      };

      expect(meBody.user.email.toLowerCase()).toBe(inviteRecipientEmail.toLowerCase());
      expect(meBody.membership.role, 'Invite-registered user must have MEMBER role').toBe('MEMBER');
    } finally {
      await freshContext.close().catch(() => undefined);
    }
  });
});
