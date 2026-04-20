import { afterEach, describe, expect, it, vi } from 'vitest';

const fetchCpAccountMock = vi.fn();
const fetchCpAccountReviewMock = vi.fn();
const fetchCpAccountsListMock = vi.fn();

vi.mock('../../../../src/features/accounts/cp-accounts-api', () => ({
  fetchCpAccount: fetchCpAccountMock,
  fetchCpAccountReview: fetchCpAccountReviewMock,
  fetchCpAccountsList: fetchCpAccountsListMock,
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe('account-loaders', () => {
  it('returns the draft account for create-flow loaders', async () => {
    fetchCpAccountMock.mockResolvedValue({
      accountKey: 'acme',
      cpStatus: 'Draft',
    });

    const { loadDraftAccountByKey } =
      await import('../../../../src/features/accounts/account-loaders');

    await expect(loadDraftAccountByKey('acme')).resolves.toMatchObject({
      accountKey: 'acme',
      cpStatus: 'Draft',
    });
    expect(fetchCpAccountMock).toHaveBeenCalledWith('acme');
  });

  it('rejects non-draft accounts from create-flow loaders', async () => {
    fetchCpAccountMock.mockResolvedValue({
      accountKey: 'acme',
      cpStatus: 'Active',
    });

    const { loadDraftAccountByKey } =
      await import('../../../../src/features/accounts/account-loaders');

    await expect(loadDraftAccountByKey('acme')).resolves.toBeNull();
    expect(fetchCpAccountMock).toHaveBeenCalledWith('acme');
  });
});
