/**
 * cp/test/unit/app/accounts/create-routing.spec.ts
 *
 * WHY:
 * - Route-level integrity coverage for the create flow.
 * - Makes create-entry, setup, personal, and review route regressions visible
 *   without requiring a browser test to catch every server-page mistake first.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

class RedirectSignal extends Error {
  path: string;

  constructor(path: string) {
    super(`redirect:${path}`);
    this.name = 'RedirectSignal';
    this.path = path;
  }
}

const redirectMock = vi.fn();
const loadDraftAccountByKeyMock = vi.fn();
const loadAccountReviewByKeyMock = vi.fn();
const accountSetupOverviewScreenMock = vi.fn();
const accountReviewScreenMock = vi.fn();
const accountPersonalConfigScreenMock = vi.fn();

vi.mock('next/navigation', () => ({
  redirect: redirectMock,
}));

vi.mock('@/features/accounts/account-loaders', () => ({
  loadDraftAccountByKey: loadDraftAccountByKeyMock,
  loadAccountReviewByKey: loadAccountReviewByKeyMock,
}));

vi.mock('@/features/accounts/screens/account-setup-overview-screen', () => ({
  AccountSetupOverviewScreen: accountSetupOverviewScreenMock,
}));

vi.mock('@/features/accounts/screens/account-review-screen', () => ({
  AccountReviewScreen: accountReviewScreenMock,
}));

vi.mock('@/features/accounts/screens/account-personal-config-screen', () => ({
  AccountPersonalConfigScreen: accountPersonalConfigScreenMock,
}));

function expectRedirectSync(run: () => unknown, expectedPath: string) {
  try {
    run();
    throw new Error(`Expected redirect to ${expectedPath}`);
  } catch (error) {
    expect(error).toBeInstanceOf(RedirectSignal);
    expect((error as RedirectSignal).path).toBe(expectedPath);
  }
}

async function expectRedirectAsync(run: () => Promise<unknown>, expectedPath: string) {
  try {
    await run();
    throw new Error(`Expected redirect to ${expectedPath}`);
  } catch (error) {
    expect(error).toBeInstanceOf(RedirectSignal);
    expect((error as RedirectSignal).path).toBe(expectedPath);
  }
}

describe('CP create-flow route integrity', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetModules();

    redirectMock.mockImplementation((path: string) => {
      throw new RedirectSignal(path);
    });
  });

  it('redirects /accounts/create to the real create Step 1 page', async () => {
    const { default: CreateAccountRedirectPage } = await import('@/app/accounts/create/page');

    expectRedirectSync(() => CreateAccountRedirectPage(), '/accounts/create/basic-info');
  });

  it('redirects create setup back to Step 1 when accountKey is missing', async () => {
    const { default: CreateAccountSetupPage } = await import('@/app/accounts/create/setup/page');

    await expectRedirectAsync(
      () =>
        CreateAccountSetupPage({
          searchParams: Promise.resolve({}),
        }),
      '/accounts/create/basic-info',
    );

    expect(loadDraftAccountByKeyMock).not.toHaveBeenCalled();
  });

  it('redirects create setup back to Step 1 when the draft account cannot be loaded', async () => {
    loadDraftAccountByKeyMock.mockResolvedValue(null);

    const { default: CreateAccountSetupPage } = await import('@/app/accounts/create/setup/page');

    await expectRedirectAsync(
      () =>
        CreateAccountSetupPage({
          searchParams: Promise.resolve({ accountKey: 'acme' }),
        }),
      '/accounts/create/basic-info',
    );

    expect(loadDraftAccountByKeyMock).toHaveBeenCalledWith('acme');
  });

  it('renders the real create Step 2 overview when the draft account exists', async () => {
    const account = {
      accountKey: 'acme',
      accountName: 'Acme',
    };

    loadDraftAccountByKeyMock.mockResolvedValue(account);

    const { default: CreateAccountSetupPage } = await import('@/app/accounts/create/setup/page');

    const element = await CreateAccountSetupPage({
      searchParams: Promise.resolve({ accountKey: 'acme' }),
    });

    expect(loadDraftAccountByKeyMock).toHaveBeenCalledWith('acme');
    expect(element).toMatchObject({
      props: {
        mode: 'create',
        account,
      },
    });
    expect(element?.type).toBe(accountSetupOverviewScreenMock);
  });

  it('redirects create review back to Step 1 when accountKey is missing', async () => {
    const { default: CreateAccountReviewPage } = await import('@/app/accounts/create/review/page');

    await expectRedirectAsync(
      () =>
        CreateAccountReviewPage({
          searchParams: Promise.resolve({}),
        }),
      '/accounts/create/basic-info',
    );

    expect(loadAccountReviewByKeyMock).not.toHaveBeenCalled();
  });

  it('redirects create review back to Step 1 when the review payload cannot be loaded', async () => {
    loadAccountReviewByKeyMock.mockResolvedValue(null);

    const { default: CreateAccountReviewPage } = await import('@/app/accounts/create/review/page');

    await expectRedirectAsync(
      () =>
        CreateAccountReviewPage({
          searchParams: Promise.resolve({ accountKey: 'acme' }),
        }),
      '/accounts/create/basic-info',
    );

    expect(loadAccountReviewByKeyMock).toHaveBeenCalledWith('acme');
  });

  it('renders the real create review page when the review payload exists', async () => {
    const review = {
      account: {
        accountKey: 'acme',
      },
    };

    loadAccountReviewByKeyMock.mockResolvedValue(review);

    const { default: CreateAccountReviewPage } = await import('@/app/accounts/create/review/page');

    const element = await CreateAccountReviewPage({
      searchParams: Promise.resolve({ accountKey: 'acme' }),
    });

    expect(loadAccountReviewByKeyMock).toHaveBeenCalledWith('acme');
    expect(element).toMatchObject({
      props: {
        mode: 'create',
        review,
      },
    });
    expect(element?.type).toBe(accountReviewScreenMock);
  });

  it('redirects create Personal back to Step 1 when accountKey is missing', async () => {
    const { default: CreatePersonalSetupPage } =
      await import('@/app/accounts/create/setup/module-settings/personal/page');

    await expectRedirectAsync(
      () =>
        CreatePersonalSetupPage({
          searchParams: Promise.resolve({}),
        }),
      '/accounts/create/basic-info',
    );

    expect(loadDraftAccountByKeyMock).not.toHaveBeenCalled();
  });

  it('redirects create Personal back to Step 1 when the draft account cannot be loaded', async () => {
    loadDraftAccountByKeyMock.mockResolvedValue(null);

    const { default: CreatePersonalSetupPage } =
      await import('@/app/accounts/create/setup/module-settings/personal/page');

    await expectRedirectAsync(
      () =>
        CreatePersonalSetupPage({
          searchParams: Promise.resolve({ accountKey: 'acme' }),
        }),
      '/accounts/create/basic-info',
    );

    expect(loadDraftAccountByKeyMock).toHaveBeenCalledWith('acme');
  });

  it('renders the create Personal page when the draft account exists', async () => {
    const account = {
      accountKey: 'acme',
      accountName: 'Acme',
    };

    loadDraftAccountByKeyMock.mockResolvedValue(account);

    const { default: CreatePersonalSetupPage } =
      await import('@/app/accounts/create/setup/module-settings/personal/page');

    const element = await CreatePersonalSetupPage({
      searchParams: Promise.resolve({ accountKey: 'acme' }),
    });

    expect(loadDraftAccountByKeyMock).toHaveBeenCalledWith('acme');
    expect(element).toMatchObject({
      props: {
        mode: 'create',
        account,
      },
    });
    expect(element?.type).toBe(accountPersonalConfigScreenMock);
  });
});
