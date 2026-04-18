/**
 * frontend/test/e2e/cp-smoke.spec.ts
 *
 * WHY:
 * - Proves the Control Plane against the real full stack and real proxy host.
 * - Exercises the minimum load-bearing operator path:
 *   open CP host → create account → save required groups → review → publish
 *   → re-enter → status toggle.
 * - Keeps the proof honest: browser uses the public CP host, backend calls stay
 *   same-origin through Caddy, and CP SSR continues to use INTERNAL_API_URL.
 *
 * PREREQUISITES:
 * - Full proxy topology must already be running.
 * - Valid environments:
 *   - CI Control Plane workflow
 *   - local full-stack mode via: yarn dev:stack
 * - This spec is NOT valid under plain host-run local dev (yarn dev), because
 *   cp.lvh.me:3000 is not the CP app entrypoint in that topology.
 * - Browser entry must be the real CP host: cp.lvh.me:3000.
 */

import { expect, test, type Page } from '@playwright/test';

const CP_ORIGIN = 'http://cp.lvh.me:3000';

function buildUniqueAccountKey(): string {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return `cp-smoke-${suffix}`;
}

async function openSetupGroup(page: Page, title: string) {
  const groupCard = page.locator('article').filter({ hasText: title });

  await expect(groupCard).toContainText(title);
  await groupCard.getByRole('link', { name: /configure group →|review group →/i }).click();
}

async function saveRequiredSetupGroup(page: Page, options: { title: string; accountKey: string }) {
  const { title, accountKey } = options;

  await openSetupGroup(page, title);
  await expect(page.getByRole('heading', { name: title })).toBeVisible();

  if (title === 'Access, Identity & Security') {
    const passwordCheckbox = page
      .locator('label')
      .filter({ hasText: 'Username & Password' })
      .locator('input[type="checkbox"]');

    await passwordCheckbox.check();
  }

  if (title === 'Module Settings') {
    const personalCheckbox = page
      .locator('label')
      .filter({ hasText: 'Personal' })
      .locator('input[type="checkbox"]')
      .first();

    if (await personalCheckbox.isChecked()) {
      await personalCheckbox.uncheck();
    }

    await expect(
      page.getByText('Personal is currently disabled, so no Personal save is required.'),
    ).toBeVisible();
  }

  await page.getByRole('button', { name: 'Save & Close' }).click();

  await expect(page).toHaveURL(`${CP_ORIGIN}/accounts/create/setup?accountKey=${accountKey}`);
  await expect(page.getByRole('heading', { name: 'Account Setup' })).toBeVisible();
}

test.describe('control plane full-stack smoke', () => {
  test('covers create, review/publish, re-entry, and status toggle on the real CP host', async ({
    page,
  }) => {
    const accountName = `CP Smoke ${Date.now()}`;
    const accountKey = buildUniqueAccountKey();

    await page.goto(`${CP_ORIGIN}/`);

    await expect(page).toHaveURL(`${CP_ORIGIN}/accounts/create/basic-info`);
    await expect(page.getByRole('heading', { name: 'Basic Account Info' })).toBeVisible();

    await page.getByLabel(/Account Name/i).fill(accountName);
    await page.getByLabel(/Account Key/i).fill(accountKey);
    await page.getByRole('button', { name: 'Continue →' }).click();

    await expect(page).toHaveURL(`${CP_ORIGIN}/accounts/create/setup?accountKey=${accountKey}`);
    await expect(page.getByRole('heading', { name: 'Account Setup' })).toBeVisible();

    await saveRequiredSetupGroup(page, {
      title: 'Access, Identity & Security',
      accountKey,
    });

    await saveRequiredSetupGroup(page, {
      title: 'Account Settings',
      accountKey,
    });

    await saveRequiredSetupGroup(page, {
      title: 'Module Settings',
      accountKey,
    });

    await expect(page.getByRole('link', { name: 'Continue →' })).toBeVisible();
    await page.getByRole('link', { name: 'Continue →' }).click();

    await expect(page).toHaveURL(`${CP_ORIGIN}/accounts/create/review?accountKey=${accountKey}`);
    await expect(page.getByRole('heading', { name: 'Review & Publish' })).toBeVisible();
    await expect(page.getByText('Activation Ready passed.')).toBeVisible();

    await page.getByRole('button', { name: 'Publish' }).click();

    await expect(page.getByText('Provisioned: Active')).toBeVisible();
    await expect(page.getByText(`http://${accountKey}.lvh.me:3000`)).toBeVisible();

    await page.goto(`${CP_ORIGIN}/accounts`);
    await expect(page.getByRole('heading', { name: 'Accounts' })).toBeVisible();

    const activeRow = page.locator('tr').filter({ hasText: accountKey });

    await expect(activeRow).toContainText(accountName);
    await expect(activeRow).toContainText('Active');

    await activeRow.getByRole('link', { name: 'Edit Setup' }).click();

    await expect(page).toHaveURL(`${CP_ORIGIN}/accounts/${accountKey}/edit/setup`);
    await expect(page.getByRole('heading', { name: 'Account Setup' })).toBeVisible();
    await expect(page.getByText(accountKey)).toBeVisible();

    await page.goto(`${CP_ORIGIN}/accounts`);

    const disableRow = page.locator('tr').filter({ hasText: accountKey });
    await disableRow.getByRole('button', { name: 'Disable' }).click();

    await expect(page.getByText(`${accountName} is now Disabled.`)).toBeVisible();
    await expect(page.locator('tr').filter({ hasText: accountKey })).toContainText('Disabled');

    const activateRow = page.locator('tr').filter({ hasText: accountKey });
    await activateRow.getByRole('button', { name: 'Activate' }).click();

    await expect(page.getByText(`${accountName} is now Active.`)).toBeVisible();
    await expect(page.locator('tr').filter({ hasText: accountKey })).toContainText('Active');
  });
});
