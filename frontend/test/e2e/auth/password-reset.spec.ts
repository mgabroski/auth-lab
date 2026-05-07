/**
 * frontend/test/e2e/auth/password-reset.spec.ts
 *
 * WHY: Split from the legacy monolithic auth.spec.ts to keep the auth proof layer navigable while preserving the exact real-stack assertions.
 */

import { expect, test } from '@playwright/test';
import { AUTH_E2E } from './auth-test-context';
import * as MAILPIT from '../helpers/mailpit';

test.describe('auth smoke: password reset', () => {
  // ── 19. Password reset full loop ──────────────────────────────────────────
  //
  // Proves:
  // - POST /auth/forgot-password delivers a reset email via real SMTP/Mailpit
  // - the reset link in the email contains a valid token and navigates to
  //   /auth/reset-password correctly
  // - POST /auth/reset-password accepts the token and the new password
  // - the user can log in with the new password
  // - the old password is rejected after reset
  //
  // Uses a dedicated E2E persona (e2e-reset-member@example.com) that no other
  // test touches. The seed restores its password on every run.

  test('password reset: forgot → email → link → new password → login → old password rejected', async ({
    page,
  }) => {
    test.setTimeout(90_000);

    const RESET_PASSWORD = `Reset${Date.now()}!`;

    await MAILPIT.purgeMailpit();

    // ── A. Navigate to forgot-password page ──────────────────────────────────

    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/forgot-password`);
    // Use level:2 to avoid strict mode violation — the page has both an h1 (tenant name)
    // and an h2 ('Request a reset link'). We want the h2 form heading specifically.
    await expect(
      page.getByRole('heading', { level: 2, name: /request a reset link/i }),
    ).toBeVisible();

    // ── B. Submit the forgot-password form ────────────────────────────────────

    await page.getByLabel('Email').fill(AUTH_E2E.E2E_RESET_MEMBER_EMAIL);
    await page.getByRole('button', { name: 'Send reset link' }).click();

    // The backend always returns the generic "Check your email" message to
    // prevent account enumeration — assert this is what the user sees.
    await expect(page.getByText('Check your email')).toBeVisible({ timeout: 10_000 });

    // ── C. Wait for the reset email in Mailpit ────────────────────────────────

    const message = await MAILPIT.waitForEmailToRecipient(AUTH_E2E.E2E_RESET_MEMBER_EMAIL);
    expect(message.Subject, 'Reset email subject must reference reset').toMatch(/reset|password/i);

    // ── D. Extract the reset link ─────────────────────────────────────────────

    const resetLink = MAILPIT.extractLinkFromText(message.Text, '/auth/reset-password?token=');
    expect(resetLink, 'Reset link must target the open tenant host').toContain(
      `${AUTH_E2E.OPEN_TENANT}.lvh.me`,
    );

    // ── E. Navigate to the reset link ─────────────────────────────────────────

    await page.goto(resetLink);
    await expect(page).toHaveURL(/\/auth\/reset-password/, { timeout: 10_000 });

    // ── F. Submit the new password ────────────────────────────────────────────

    await page.getByLabel('New password').fill(RESET_PASSWORD);
    await page.getByRole('button', { name: /reset|update|save/i }).click();

    // Backend returns "Password updated successfully. Please sign in with your new password."
    // Target exact substring to avoid matching the "sign in" navigation links also on the page.
    await expect(page.getByText('Password updated successfully')).toBeVisible({ timeout: 10_000 });

    // ── G. Login with the new password ────────────────────────────────────────

    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(AUTH_E2E.E2E_RESET_MEMBER_EMAIL);
    await page.getByLabel('Password').fill(RESET_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/app`, { timeout: 15_000 });

    const meRes = await page.request.get(`${AUTH_E2E.OPEN_ORIGIN}/api/auth/me`);
    expect(meRes.status(), '/api/auth/me must be 200 after reset login').toBe(200);

    // ── H. Confirm old password is rejected ───────────────────────────────────

    await page.request.post(`${AUTH_E2E.OPEN_ORIGIN}/api/auth/logout`);

    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(AUTH_E2E.E2E_RESET_MEMBER_EMAIL);
    await page.getByLabel('Password').fill(AUTH_E2E.MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    const loginError = page
      .locator('[role="alert"]')
      .filter({ hasText: /invalid credentials|incorrect|wrong|something went wrong/i })
      .first();

    await expect(loginError).toBeVisible({ timeout: 10_000 });

    await expect(page).not.toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/app`);
    // No restore needed — the seed resets e2e-reset-member's password to
    // Password123! on every run, so the next run always starts clean.
  });
});
