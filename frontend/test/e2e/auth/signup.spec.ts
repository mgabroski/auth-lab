/**
 * frontend/test/e2e/auth/signup.spec.ts
 *
 * WHY: Split from the legacy monolithic auth.spec.ts to keep the auth proof layer navigable while preserving the exact real-stack assertions.
 */

import { expect, test } from '@playwright/test';
import { AUTH_E2E } from './auth-test-context';
import * as MAILPIT from '../helpers/mailpit';

test.describe('auth smoke: public signup and signup policy', () => {
  // ── 4. Public signup → email verification → authenticated ─────────────────
  //
  // Proves:
  // - POST /api/auth/signup works against the real DB
  // - the backend enqueues an outbox message and delivers it to Mailpit via SMTP
  // - the verification link is tenant-shaped and contains a valid token
  // - navigating to the verify link completes verification and creates a session

  test('signup delivers verification email and verify-link completes auth', async ({ page }) => {
    const email = `e2e-signup-${Date.now()}@example.com`;

    await MAILPIT.purgeMailpit();

    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/signup`);
    await expect(page.getByRole('heading', { name: /create your/i })).toBeVisible();

    await page.getByLabel('Full name').fill('E2E Signup User');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill('Password123!');
    await page.getByRole('button', { name: 'Create account' }).click();

    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/verify-email`);

    const message = await MAILPIT.waitForEmailToRecipient(email);
    expect(message.Subject).toMatch(/verify/i);

    const verifyLink = MAILPIT.extractLinkFromText(message.Text, '/verify-email?token=');
    expect(verifyLink).toContain(`${AUTH_E2E.OPEN_TENANT}.lvh.me`);

    await page.goto(verifyLink);
    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/app`);
    await expect(page.getByRole('heading', { name: 'Member app' })).toBeVisible();
    await expect(page.getByText('Authenticated handoff complete')).toBeVisible();
  });

  // ── 5. Signup blocked on invite-only tenant ───────────────────────────────

  test('signup page shows blocked state on invite-only tenant', async ({ page }) => {
    await page.goto(`${AUTH_E2E.INVITE_ONLY_ORIGIN}/auth/signup`);

    await expect(page.getByText(/sign up is disabled/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create account' })).toHaveCount(0);
  });
});
