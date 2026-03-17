import { expect, test } from '@playwright/test';

type MockMailMessage = {
  type: 'email.verify' | 'password.reset';
  email: string;
  token: string;
  link: string;
  createdAt: number;
};

async function resetMockBackend(request: { post: (url: string) => Promise<unknown> }) {
  await request.post('http://127.0.0.1:3101/__test/reset');
}

async function listMockMessages(
  request: { get: (url: string) => Promise<{ ok: () => boolean; json: () => Promise<unknown> }> },
  opts: { type: MockMailMessage['type']; email: string },
): Promise<MockMailMessage[]> {
  const response = await request.get(
    `http://127.0.0.1:3101/__mail/messages?type=${encodeURIComponent(opts.type)}&email=${encodeURIComponent(opts.email)}`,
  );

  expect(response.ok()).toBeTruthy();

  const body = (await response.json()) as { messages: MockMailMessage[] };
  return body.messages;
}

async function expireMockToken(
  request: {
    post: (
      url: string,
      options: { data: { type: MockMailMessage['type']; token: string } },
    ) => Promise<{ ok: () => boolean }>;
  },
  opts: { type: MockMailMessage['type']; token: string },
) {
  const response = await request.post('http://127.0.0.1:3101/__tokens/expire', {
    data: opts,
  });

  expect(response.ok()).toBeTruthy();
}

test.describe('frontend auth flows', () => {
  test.beforeEach(async ({ request }) => {
    await resetMockBackend(request);
  });

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
    await expect(page.getByRole('img', { name: 'Authenticator QR code' })).toBeVisible();
    await expect(page.getByText(/expected app entry/i)).toBeVisible();
    await expect(page.getByText(/issuer:/i)).toBeVisible();
    await expect(page.getByText(/account label:/i)).toBeVisible();
    await expect(page.getByLabel('Authenticator secret')).toHaveValue('ABCDEF123456');

    await page.getByLabel('6-digit code').fill('123456');
    await page.getByRole('button', { name: 'Finish MFA setup' }).click();

    await expect(page).toHaveURL(/\/admin$/);
    await expect(page.getByRole('heading', { name: 'Admin dashboard' })).toBeVisible();
    await expect(page.getByText('Admin landing ready')).toBeVisible();
  });

  test('public signup can resend verification, invalidates the old token, and the fresh email link completes verification', async ({
    page,
    request,
  }) => {
    const email = `signup-${Date.now()}@example.com`;
    const password = 'Password123!';

    await page.goto('/auth/signup');

    await expect(page.getByRole('heading', { name: /create your acme account/i })).toBeVisible();

    await page.getByLabel('Full name').fill('Signup User');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button', { name: 'Create account' }).click();

    await expect(page).toHaveURL(/\/verify-email$/);
    await expect(page.getByRole('heading', { name: /verify your acme email/i })).toBeVisible();
    await expect(page.getByText(/this page is missing a verification token/i)).toBeVisible();

    const firstBatch = await listMockMessages(request, {
      type: 'email.verify',
      email,
    });
    expect(firstBatch).toHaveLength(1);
    const firstLink = firstBatch[0].link;
    const firstToken = firstBatch[0].token;

    await page.getByRole('button', { name: 'Resend verification email' }).click();
    await expect(
      page.getByText(/if your email is unverified, a new verification link has been sent/i),
    ).toBeVisible();

    const secondBatch = await listMockMessages(request, {
      type: 'email.verify',
      email,
    });
    expect(secondBatch).toHaveLength(2);
    const secondLink = secondBatch[1].link;
    const secondToken = secondBatch[1].token;

    expect(secondToken).not.toBe(firstToken);

    await page.goto(firstLink);
    await expect(page).toHaveURL(/\/verify-email\?token=/);
    await expect(
      page
        .locator('[role="alert"]')
        .filter({ hasText: /invalid or has expired/i })
        .first(),
    ).toBeVisible();

    await page.goto(secondLink);
    await expect(page).toHaveURL(/\/app$/);
    await expect(page.getByRole('heading', { name: 'Member app' })).toBeVisible();

    await page.getByRole('button', { name: 'Log out' }).click();
    await expect(page).toHaveURL(/\/auth\/login$/);

    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(/\/app$/);
    await expect(page.getByText('Authenticated handoff complete')).toBeVisible();
  });

  test('signup page renders the blocked state when tenant signup is disabled', async ({ page }) => {
    await page.goto('http://inviteonly.localhost:3100/auth/signup');

    await expect(
      page.getByRole('heading', { name: /create your invite only account/i }),
    ).toBeVisible();
    await expect(page.getByText(/sign up is disabled for this workspace/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create account' })).toHaveCount(0);
  });

  test('forgot-password email link resets the password, old credentials stop working, and new credentials work', async ({
    page,
    request,
  }) => {
    const originalPassword = 'Password123!';
    const newPassword = 'FreshPass456!';
    const email = 'member@example.com';

    await page.goto('/auth/forgot-password');
    await page.getByLabel('Email').fill(email);
    await page.getByRole('button', { name: 'Send reset link' }).click();

    await expect(page.getByText(/if an account matches that email/i)).toBeVisible();

    const resetMessages = await listMockMessages(request, {
      type: 'password.reset',
      email,
    });
    expect(resetMessages).toHaveLength(1);

    await page.goto(resetMessages[0].link);
    await expect(page.getByRole('heading', { name: /reset your acme password/i })).toBeVisible();

    await page.getByLabel('New password').fill(newPassword);
    await page.getByRole('button', { name: 'Update password' }).click();

    await expect(page.getByText(/your password has been reset/i)).toBeVisible();

    await page.goto('/auth/login');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(originalPassword);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(
      page
        .locator('[role="alert"]')
        .filter({ hasText: /invalid email or password/i })
        .first(),
    ).toBeVisible();

    await page.getByLabel('Password').fill(newPassword);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(/\/app$/);
    await expect(page.getByRole('heading', { name: 'Member app' })).toBeVisible();
  });

  test('expired and reused reset-password links fail in the browser', async ({ page, request }) => {
    const email = 'member@example.com';

    await page.goto('/auth/forgot-password');
    await page.getByLabel('Email').fill(email);
    await page.getByRole('button', { name: 'Send reset link' }).click();
    await expect(page.getByText(/if an account matches that email/i)).toBeVisible();

    const firstBatch = await listMockMessages(request, {
      type: 'password.reset',
      email,
    });
    expect(firstBatch).toHaveLength(1);

    await expireMockToken(request, {
      type: 'password.reset',
      token: firstBatch[0].token,
    });

    await page.goto(firstBatch[0].link);
    await page.getByLabel('New password').fill('ExpiredPass123!');
    await page.getByRole('button', { name: 'Update password' }).click();

    await expect(
      page
        .locator('[role="alert"]')
        .filter({ hasText: /invalid or has expired/i })
        .first(),
    ).toBeVisible();

    await page.goto('/auth/forgot-password');
    await page.getByLabel('Email').fill(email);
    await page.getByRole('button', { name: 'Send reset link' }).click();
    await expect(page.getByText(/if an account matches that email/i)).toBeVisible();

    const secondBatch = await listMockMessages(request, {
      type: 'password.reset',
      email,
    });
    expect(secondBatch).toHaveLength(2);

    const freshLink = secondBatch[1].link;

    await page.goto(freshLink);
    await page.getByLabel('New password').fill('ReusablePass789!');
    await page.getByRole('button', { name: 'Update password' }).click();
    await expect(page.getByText(/your password has been reset/i)).toBeVisible();

    await page.goto(freshLink);
    await page.getByLabel('New password').fill('ShouldFailAgain123!');
    await page.getByRole('button', { name: 'Update password' }).click();

    await expect(
      page
        .locator('[role="alert"]')
        .filter({ hasText: /invalid or has expired/i })
        .first(),
    ).toBeVisible();
  });
});
