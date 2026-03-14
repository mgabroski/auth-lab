import { expect, test } from '@playwright/test';

test.describe('frontend auth flows', () => {
  test('member login follows backend nextAction NONE into /app and logout returns to public entry', async ({
    page,
  }) => {
    await page.goto('/auth/login');

    await expect(page.getByRole('heading', { name: /sign in to acme/i })).toBeVisible();

    await page.getByLabel('Email').fill('member@example.com');
    await page.getByLabel('Password').fill('Password123!');
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(/\/app$/);
    await expect(page.getByRole('heading', { name: 'Member app' })).toBeVisible();
    await expect(page.getByText('Authenticated handoff complete')).toBeVisible();

    await page.getByRole('button', { name: 'Log out' }).click();
    await expect(page).toHaveURL(/\/auth\/login$/);
    await expect(page.getByRole('heading', { name: /sign in to acme/i })).toBeVisible();
  });

  test('admin login follows backend continuation truth into MFA setup and then lands on /admin', async ({
    page,
  }) => {
    await page.goto('/auth/login');

    await page.getByLabel('Email').fill('admin@example.com');
    await page.getByLabel('Password').fill('Password123!');
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(/\/auth\/mfa\/setup$/);
    await expect(
      page.getByRole('heading', { name: /set up multi-factor authentication/i }),
    ).toBeVisible();
    await expect(page.getByLabel('Authenticator secret')).toHaveValue('ABCDEF123456');

    await page.getByLabel('6-digit code').fill('123456');
    await page.getByRole('button', { name: 'Finish MFA setup' }).click();

    await expect(page).toHaveURL(/\/admin$/);
    await expect(page.getByRole('heading', { name: 'Admin dashboard' })).toBeVisible();
    await expect(page.getByText('Admin landing ready')).toBeVisible();
  });

  test('public signup follows backend EMAIL_VERIFICATION_REQUIRED continuation and can resend verification', async ({
    page,
  }) => {
    await page.goto('/auth/signup');

    await expect(page.getByRole('heading', { name: /create your acme account/i })).toBeVisible();

    await page.getByLabel('Full name').fill('Signup User');
    await page.getByLabel('Email').fill('signup@example.com');
    await page.getByLabel('Password').fill('Password123!');
    await page.getByRole('button', { name: 'Create account' }).click();

    await expect(page).toHaveURL(/\/verify-email$/);
    await expect(page.getByRole('heading', { name: /verify your acme email/i })).toBeVisible();
    await expect(page.getByText(/this page is missing a verification token/i)).toBeVisible();

    await page.getByRole('button', { name: 'Resend verification email' }).click();
    await expect(
      page.getByText(/if your email is unverified, a new verification link has been sent/i),
    ).toBeVisible();
  });
});
