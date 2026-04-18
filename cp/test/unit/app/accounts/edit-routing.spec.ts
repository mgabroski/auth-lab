/**
 * cp/test/unit/app/accounts/edit-routing.spec.ts
 *
 * WHY:
 * - Route-level integrity coverage for the edit / re-entry flow.
 * - Makes edit entry, blocked basic-info edit, review, Personal, and setup-group
 *   regressions detectable at the server-page layer.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

interface TestElement {
  type: unknown;
  props: {
    mode?: string;
    account?: Record<string, unknown>;
    review?: Record<string, unknown>;
    group?: {
      slug: string;
      title: string;
    };
  };
}

class RedirectSignal extends Error {
  path: string;

  constructor(path: string) {
    super(`redirect:${path}`);
    this.name = 'RedirectSignal';
    this.path = path;
  }
}

class NotFoundSignal extends Error {
  constructor() {
    super('notFound');
    this.name = 'NotFoundSignal';
  }
}

const redirectMock = vi.fn();
const notFoundMock = vi.fn();
const loadEditableAccountMock = vi.fn();
const loadAccountReviewByKeyMock = vi.fn();
const accountSetupOverviewScreenMock = vi.fn();
const accountReviewScreenMock = vi.fn();
const accountPersonalConfigScreenMock = vi.fn();
const accountSetupGroupScreenMock = vi.fn();

vi.mock('next/navigation', () => ({
  redirect: redirectMock,
  notFound: notFoundMock,
}));

vi.mock('@/features/accounts/account-loaders', () => ({
  loadEditableAccount: loadEditableAccountMock,
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

vi.mock('@/features/accounts/screens/account-setup-group-screen', () => ({
  AccountSetupGroupScreen: accountSetupGroupScreenMock,
}));

async function expectNotFoundAsync(run: () => Promise<unknown>) {
  try {
    await run();
    throw new Error('Expected notFound()');
  } catch (error) {
    expect(error).toBeInstanceOf(NotFoundSignal);
  }
}

describe('CP edit-flow route integrity', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    redirectMock.mockImplementation((path: string) => {
      throw new RedirectSignal(path);
    });

    notFoundMock.mockImplementation(() => {
      throw new NotFoundSignal();
    });
  });

  it('redirects /accounts/[accountKey]/edit to the real Step 2 edit entry page', async () => {
    const { default: EditAccountRedirectPage } =
      await import('@/app/accounts/[accountKey]/edit/page');

    await expect(
      EditAccountRedirectPage({
        params: Promise.resolve({ accountKey: 'acme' }),
      }),
    ).rejects.toMatchObject({
      path: '/accounts/acme/edit/setup',
    });
  });

  it('redirects edit basic-info back to Step 2 because Step 1 is not a valid edit surface', async () => {
    const { default: EditAccountBasicInfoPage } =
      await import('@/app/accounts/[accountKey]/edit/basic-info/page');

    await expect(
      EditAccountBasicInfoPage({
        params: Promise.resolve({ accountKey: 'acme' }),
      }),
    ).rejects.toMatchObject({
      path: '/accounts/acme/edit/setup',
    });
  });

  it('renders the real edit Step 2 overview when the editable account exists', async () => {
    const account = {
      accountKey: 'acme',
      accountName: 'Acme',
    };

    loadEditableAccountMock.mockResolvedValue(account);

    const { default: EditAccountSetupPage } =
      await import('@/app/accounts/[accountKey]/edit/setup/page');

    const element = (await EditAccountSetupPage({
      params: Promise.resolve({ accountKey: 'acme' }),
    })) as unknown as TestElement;

    expect(loadEditableAccountMock).toHaveBeenCalledWith('acme');
    expect(notFoundMock).not.toHaveBeenCalled();
    expect(element).toMatchObject({
      props: {
        mode: 'edit',
        account,
      },
    });
    expect(element.type).toBe(accountSetupOverviewScreenMock);
  });

  it('returns notFound for edit setup when the account cannot be loaded', async () => {
    loadEditableAccountMock.mockResolvedValue(null);

    const { default: EditAccountSetupPage } =
      await import('@/app/accounts/[accountKey]/edit/setup/page');

    await expectNotFoundAsync(() =>
      EditAccountSetupPage({
        params: Promise.resolve({ accountKey: 'acme' }),
      }),
    );
  });

  it('renders the edit review page when the review payload exists', async () => {
    const review = {
      account: {
        accountKey: 'acme',
      },
    };

    loadAccountReviewByKeyMock.mockResolvedValue(review);

    const { default: EditAccountReviewPage } =
      await import('@/app/accounts/[accountKey]/review/page');

    const element = (await EditAccountReviewPage({
      params: Promise.resolve({ accountKey: 'acme' }),
    })) as unknown as TestElement;

    expect(loadAccountReviewByKeyMock).toHaveBeenCalledWith('acme');
    expect(element).toMatchObject({
      props: {
        mode: 'edit',
        review,
      },
    });
    expect(element.type).toBe(accountReviewScreenMock);
  });

  it('returns notFound for edit review when the review payload is missing', async () => {
    loadAccountReviewByKeyMock.mockResolvedValue(null);

    const { default: EditAccountReviewPage } =
      await import('@/app/accounts/[accountKey]/review/page');

    await expectNotFoundAsync(() =>
      EditAccountReviewPage({
        params: Promise.resolve({ accountKey: 'acme' }),
      }),
    );
  });

  it('renders the edit Personal page when the editable account exists', async () => {
    const account = {
      accountKey: 'acme',
      accountName: 'Acme',
    };

    loadEditableAccountMock.mockResolvedValue(account);

    const { default: EditPersonalSetupPage } =
      await import('@/app/accounts/[accountKey]/edit/setup/module-settings/personal/page');

    const element = (await EditPersonalSetupPage({
      params: Promise.resolve({ accountKey: 'acme' }),
    })) as unknown as TestElement;

    expect(loadEditableAccountMock).toHaveBeenCalledWith('acme');
    expect(element).toMatchObject({
      props: {
        mode: 'edit',
        account,
      },
    });
    expect(element.type).toBe(accountPersonalConfigScreenMock);
  });

  it('returns notFound for edit Personal when the editable account is missing', async () => {
    loadEditableAccountMock.mockResolvedValue(null);

    const { default: EditPersonalSetupPage } =
      await import('@/app/accounts/[accountKey]/edit/setup/module-settings/personal/page');

    await expectNotFoundAsync(() =>
      EditPersonalSetupPage({
        params: Promise.resolve({ accountKey: 'acme' }),
      }),
    );
  });

  it('renders the edit setup-group page for a valid group slug', async () => {
    const account = {
      accountKey: 'acme',
      accountName: 'Acme',
    };

    loadEditableAccountMock.mockResolvedValue(account);

    const { default: EditSetupGroupPage } =
      await import('@/app/accounts/[accountKey]/edit/setup/[groupSlug]/page');

    const element = (await EditSetupGroupPage({
      params: Promise.resolve({
        accountKey: 'acme',
        groupSlug: 'module-settings',
      }),
    })) as unknown as TestElement;

    expect(loadEditableAccountMock).toHaveBeenCalledWith('acme');
    expect(element).toMatchObject({
      props: {
        mode: 'edit',
        account,
      },
    });
    expect(element.props.group?.slug).toBe('module-settings');
    expect(element.props.group?.title).toBe('Module Settings');
    expect(element.type).toBe(accountSetupGroupScreenMock);
  });

  it('returns notFound for edit setup-group when the slug is invalid', async () => {
    loadEditableAccountMock.mockResolvedValue({
      accountKey: 'acme',
      accountName: 'Acme',
    });

    const { default: EditSetupGroupPage } =
      await import('@/app/accounts/[accountKey]/edit/setup/[groupSlug]/page');

    await expectNotFoundAsync(() =>
      EditSetupGroupPage({
        params: Promise.resolve({
          accountKey: 'acme',
          groupSlug: 'not-a-real-group',
        }),
      }),
    );
  });

  it('returns notFound for edit setup-group when the account is missing', async () => {
    loadEditableAccountMock.mockResolvedValue(null);

    const { default: EditSetupGroupPage } =
      await import('@/app/accounts/[accountKey]/edit/setup/[groupSlug]/page');

    await expectNotFoundAsync(() =>
      EditSetupGroupPage({
        params: Promise.resolve({
          accountKey: 'acme',
          groupSlug: 'module-settings',
        }),
      }),
    );
  });
});
