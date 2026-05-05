/**
 * frontend/test/e2e/settings.spec.ts
 *
 * WHY:
 * - Proves the shipped Settings v1 tenant-admin slice in a real browser against
 *   the real frontend, backend, database, SSR route gating, same-origin proxy,
 *   and host-derived tenant boundary.
 * - Complements backend contract tests: this spec verifies the visible admin
 *   journey and topology-sensitive browser behavior rather than product rules in
 *   isolation.
 *
 * PREREQUISITES:
 * - Run from a clean seeded local state before this spec:
 *   yarn reset-db && yarn dev
 * - The e2e admin starts without MFA, then this spec completes MFA through the
 *   real frontend before entering /admin.
 */

import { expect, test, type Page } from '@playwright/test';
import { generateTotp } from './helpers/totp';

const PROXY_PORT = 3000;
const OPEN_TENANT = 'goodwill-open';
const INVITE_ONLY_TENANT = 'goodwill-ca';

const OPEN_ORIGIN = `http://${OPEN_TENANT}.lvh.me:${PROXY_PORT}`;
const INVITE_ONLY_ORIGIN = `http://${INVITE_ONLY_TENANT}.lvh.me:${PROXY_PORT}`;

const E2E_ADMIN_EMAIL = 'e2e-admin@example.com';
const E2E_ADMIN_PASSWORD = 'Password123!';

async function loginAdminAndCompleteMfa(page: Page): Promise<void> {
  await page.goto(`${OPEN_ORIGIN}/auth/login`);
  await page.getByLabel('Email').fill(E2E_ADMIN_EMAIL);
  await page.getByLabel('Password').fill(E2E_ADMIN_PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();

  if (page.url() === `${OPEN_ORIGIN}/admin`) {
    return;
  }

  await expect(page).toHaveURL(`${OPEN_ORIGIN}/auth/mfa/setup`);
  await expect(page.getByRole('heading', { name: /multi-factor authentication/i })).toBeVisible();

  const secretInput = page.getByLabel('Authenticator secret');
  const errorLocator = page.getByRole('alert').filter({ hasText: /error|failed|wrong/i });

  const which = await Promise.race([
    secretInput.waitFor({ state: 'visible' }).then(() => 'secret' as const),
    errorLocator.waitFor({ state: 'visible' }).then(() => 'error' as const),
  ]);

  if (which === 'error') {
    const errorText = await errorLocator.textContent().catch(() => '(unreadable)');
    throw new Error(
      `MFA setup page showed an error instead of a secret. ` +
        `Run yarn reset-db before this Settings E2E proof. Error: ${errorText}`,
    );
  }

  const base32Secret = await secretInput.inputValue();
  const codeInput = page.getByLabel('6-digit code');
  await codeInput.fill(generateTotp(base32Secret, 0));
  await page.getByRole('button', { name: 'Finish MFA setup' }).click();
  await expect(page).toHaveURL(`${OPEN_ORIGIN}/admin`);
}

test.describe('settings tenant-admin proof', () => {
  test('covers admin banner, Settings routes, explicit saves, placeholders, and absent Permissions', async ({
    page,
  }) => {
    await loginAdminAndCompleteMfa(page);

    await expect(page.getByRole('heading', { name: 'Admin dashboard' })).toBeVisible();
    await expect(
      page.getByRole('alert', { name: 'Workspace setup requires attention' }),
    ).toBeVisible();
    await page.getByRole('link', { name: 'Open workspace settings →' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/admin/settings`);
    await expect(page.getByRole('heading', { name: 'Workspace settings' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Required sections' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Optional sections' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Access & Security' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Modules' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Communications' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Workspace Experience' })).toBeVisible();
    await expect(page.getByText('Permissions')).toHaveCount(0);

    await page.goto(`${OPEN_ORIGIN}/admin/settings/access`);
    await expect(page.getByRole('heading', { name: 'Access & Security' })).toBeVisible();
    await expect(page.getByText('Explicit review acknowledgement')).toBeVisible();
    await page.getByRole('button', { name: /Acknowledge/i }).click();
    await expect(page.getByText('Review saved')).toBeVisible();

    await page.goto(`${OPEN_ORIGIN}/admin/settings/account`);
    await expect(page.getByRole('heading', { name: 'Account Settings' })).toBeVisible();
    await expect(page.getByText('Branding')).toBeVisible();
    await expect(page.getByText('Organization Structure')).toBeVisible();
    await expect(page.getByText('Company Calendar')).toBeVisible();

    await page.goto(`${OPEN_ORIGIN}/admin/settings/modules`);
    await expect(page.getByRole('heading', { name: 'Modules' })).toBeVisible();
    await expect(page.getByText('Personal')).toBeVisible();
    await expect(page.getByText('Documents')).toBeVisible();
    await expect(page.getByText('Benefits')).toBeVisible();
    await expect(page.getByText('Payments')).toBeVisible();

    await page.goto(`${OPEN_ORIGIN}/admin/settings/modules/personal`);
    await expect(page.getByRole('heading', { name: 'Personal settings' })).toBeVisible();
    await expect(
      page.getByText('This is the one authoritative save action for Family Review'),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Save Personal Configuration' }).click();
    await expect(page.getByText('Personal configuration saved')).toBeVisible();

    await page.goto(`${OPEN_ORIGIN}/admin`);
    await expect(page.getByRole('heading', { name: 'Admin dashboard' })).toBeVisible();
    await expect(
      page.getByRole('alert', { name: 'Workspace setup requires attention' }),
    ).toHaveCount(0);

    await page.goto(`${OPEN_ORIGIN}/admin/settings/integrations`);
    await expect(page.getByRole('heading', { name: 'Integrations' })).toBeVisible();
    await expect(page.getByText('No tenant credential entry in v1.')).toBeVisible();

    await page.goto(`${OPEN_ORIGIN}/admin/settings/communications`);
    await expect(page.getByRole('heading', { name: 'Communications' })).toBeVisible();
    await expect(page.getByText('Live configuration available: no')).toBeVisible();

    const workspaceResponse = await page.request.get(
      `${OPEN_ORIGIN}/admin/settings/workspace-experience`,
    );
    expect(workspaceResponse.status(), 'Workspace Experience must remain overview-card-only').toBe(
      404,
    );

    const permissionsResponse = await page.request.get(`${OPEN_ORIGIN}/admin/settings/permissions`);
    expect(permissionsResponse.status(), 'Permissions route must remain absent in v1').toBe(404);

    const ownTenant = await page.request.get(`${OPEN_ORIGIN}/api/settings/bootstrap`);
    expect(
      ownTenant.status(),
      'authenticated Settings bootstrap must work on the admin tenant',
    ).toBe(200);

    const crossTenant = await page.request.get(`${INVITE_ONLY_ORIGIN}/api/settings/bootstrap`);
    expect(
      crossTenant.status(),
      'the same browser context must not authenticate Settings bootstrap on another tenant host',
    ).toBe(401);

    const directBackendOrigin = await page.request.get('http://localhost:3001/settings/bootstrap');
    expect(
      directBackendOrigin.status(),
      'direct backend origin is not a valid authenticated browser Settings path',
    ).toBe(401);
  });
});
