import { describe, expect, it, vi } from 'vitest';

const loadEditableAccountMock = vi.fn();
const accountSetupOverviewScreenMock = vi.fn();
const notFoundMock = vi.fn();

vi.mock('@/features/accounts/account-loaders', () => ({
  loadEditableAccount: loadEditableAccountMock,
}));

vi.mock('@/features/accounts/screens/account-setup-overview-screen', () => ({
  AccountSetupOverviewScreen: accountSetupOverviewScreenMock,
}));

vi.mock('next/navigation', () => ({
  notFound: notFoundMock,
}));

describe('EditAccountSetupPage', () => {
  it('re-enters existing accounts at the real Step 2 setup overview', async () => {
    const account = {
      accountKey: 'acme',
      accountName: 'Acme',
    };

    loadEditableAccountMock.mockResolvedValue(account);

    const { default: EditAccountSetupPage } =
      await import('@/app/accounts/[accountKey]/edit/setup/page');

    const element = await EditAccountSetupPage({
      params: Promise.resolve({ accountKey: 'acme' }),
    });

    expect(loadEditableAccountMock).toHaveBeenCalledWith('acme');
    expect(notFoundMock).not.toHaveBeenCalled();
    expect(element).toMatchObject({
      props: {
        mode: 'edit',
        account,
      },
    });
    expect(element?.type).toBe(accountSetupOverviewScreenMock);
  });
});
