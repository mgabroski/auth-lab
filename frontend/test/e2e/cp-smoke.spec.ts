/**
 * frontend/test/e2e/cp-smoke.spec.ts
 *
 * WHY:
 * - Proves the Control Plane against the real full stack and real proxy host.
 * - Exercises the minimum load-bearing operator paths:
 *   1) open CP host → create account → save required groups → review → publish
 *      → re-enter → status toggle
 *   2) Personal-enabled branch remains real end-to-end
 *   3) tenant hosts must not reach /api/cp/*
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
const TENANT_ORIGIN = 'http://goodwill-ca.lvh.me:3000';
const CP_NAVIGATION_TIMEOUT_MS = 20_000;

async function expectCpUrl(page: Page, url: string) {
  await expect(page).toHaveURL(url, { timeout: CP_NAVIGATION_TIMEOUT_MS });
}

function exactTextPattern(value: string): RegExp {
  return new RegExp(`^${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
}

async function expectMainHeading(page: Page, title: string) {
  await expect(page.locator('h1').filter({ hasText: exactTextPattern(title) })).toBeVisible();
}

function buildUniqueAccountKey(prefix = 'cp-smoke'): string {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return `${prefix}-${suffix}`;
}

async function openSetupGroup(page: Page, title: string) {
  // WHY:
  // - Setup group cards contain the title plus status/help text, so an anchored
  //   hasText regexp on the whole <article> is too strict and returns no card.
  // - Match the exact title as a child text node, then require the real group CTA
  //   so summary/status cards cannot be selected by accident.
  const groupCard = page
    .locator('article')
    .filter({ has: page.getByRole('link', { name: /^(configure group →|review group →)$/i }) })
    .filter({ has: page.getByText(title, { exact: true }) })
    .first();

  await expect(groupCard).toBeVisible();
  await groupCard.getByRole('link', { name: /^(configure group →|review group →)$/i }).click();
}

async function saveRequiredSetupGroup(page: Page, options: { title: string; accountKey: string }) {
  const { title, accountKey } = options;

  await openSetupGroup(page, title);
  await expectMainHeading(page, title);

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

  await expectCpUrl(page, `${CP_ORIGIN}/accounts/create/setup?accountKey=${accountKey}`);
  await expectMainHeading(page, 'Account Setup');
}

test.describe('control plane full-stack smoke', () => {
  test('covers create, review/publish, re-entry, and status toggle on the real CP host', async ({
    page,
  }) => {
    const accountName = `CP Smoke ${Date.now()}`;
    const accountKey = buildUniqueAccountKey();

    await page.goto(CP_ORIGIN);

    await expectCpUrl(page, `${CP_ORIGIN}/accounts/create/basic-info`);
    await expectMainHeading(page, 'Basic Account Info');

    await page.getByLabel(/Account Name/i).fill(accountName);
    await page.getByLabel(/Account Key/i).fill(accountKey);
    await page.getByRole('button', { name: 'Continue →' }).click();

    await expectCpUrl(page, `${CP_ORIGIN}/accounts/create/setup?accountKey=${accountKey}`);
    await expectMainHeading(page, 'Account Setup');

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

    await expectCpUrl(page, `${CP_ORIGIN}/accounts/create/review?accountKey=${accountKey}`);
    await expectMainHeading(page, 'Review & Publish');
    await expect(page.getByText('Activation Ready passed.')).toBeVisible();

    await page.getByRole('button', { name: 'Publish' }).click();

    await expect(page.getByText('Provisioned: Active')).toBeVisible();
    await expect(page.getByText(`http://${accountKey}.lvh.me:3000`)).toBeVisible();

    await page.goto(`${CP_ORIGIN}/accounts`);
    await expectMainHeading(page, 'Accounts');

    const activeRow = page.locator('tr').filter({ hasText: accountKey });

    await expect(activeRow).toContainText(accountName);
    await expect(activeRow).toContainText('Active');

    await activeRow.getByRole('link', { name: 'Edit Setup' }).click();

    await expectCpUrl(page, `${CP_ORIGIN}/accounts/${accountKey}/edit/setup`);
    await expectMainHeading(page, 'Account Setup');
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

  test('keeps the Personal-enabled branch real and requires the Personal sub-page before review unlocks', async ({
    page,
  }) => {
    const accountName = `CP Personal ${Date.now()}`;
    const accountKey = buildUniqueAccountKey('cp-personal');

    await page.goto(`${CP_ORIGIN}/accounts/create/basic-info`);
    await page.getByLabel(/Account Name/i).fill(accountName);
    await page.getByLabel(/Account Key/i).fill(accountKey);
    await page.getByRole('button', { name: 'Continue →' }).click();

    await saveRequiredSetupGroup(page, {
      title: 'Access, Identity & Security',
      accountKey,
    });

    await saveRequiredSetupGroup(page, {
      title: 'Account Settings',
      accountKey,
    });

    await openSetupGroup(page, 'Module Settings');
    await expectMainHeading(page, 'Module Settings');

    const personalCheckbox = page
      .locator('label')
      .filter({ hasText: 'Personal' })
      .locator('input[type="checkbox"]')
      .first();

    await personalCheckbox.check();
    await page.getByRole('button', { name: 'Save & Close' }).click();

    await expectCpUrl(page, `${CP_ORIGIN}/accounts/create/setup?accountKey=${accountKey}`);
    await expect(page.getByRole('button', { name: 'Continue →' })).toBeDisabled();

    await openSetupGroup(page, 'Module Settings');
    await page.getByRole('link', { name: 'Open Personal CP sub-page →' }).click();

    await expectMainHeading(page, 'Personal CP field configuration');
    await expect(page.getByText('Personal save state')).toBeVisible();

    await page.getByRole('button', { name: 'Save & Close' }).click();

    await expectCpUrl(
      page,
      `${CP_ORIGIN}/accounts/create/setup/module-settings?accountKey=${accountKey}`,
    );
    await expect(
      page.getByText('Personal catalog decisions have already been saved for this account.'),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Save & Close' }).click();

    await expectCpUrl(page, `${CP_ORIGIN}/accounts/create/setup?accountKey=${accountKey}`);
    await expect(page.getByRole('link', { name: 'Continue →' })).toBeVisible();

    await page.getByRole('link', { name: 'Continue →' }).click();
    await expectCpUrl(page, `${CP_ORIGIN}/accounts/create/review?accountKey=${accountKey}`);
    await expect(page.getByText('Activation Ready passed.')).toBeVisible();
  });

  test('tenant hosts reject /api/cp/* so the tenant surface cannot reach the CP backend', async ({
    page,
  }) => {
    const response = await page.request.get(`${TENANT_ORIGIN}/api/cp/accounts`);
    expect(response.status()).toBe(404);
  });
});
