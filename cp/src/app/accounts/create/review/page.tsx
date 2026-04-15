import { redirect } from 'next/navigation';
import { loadDraftAccountByKey } from '@/features/accounts/mock-data';
import { AccountReviewScreen } from '@/features/accounts/screens/account-review-screen';
import { getCreateBasicInfoPath } from '@/shared/cp/links';

type CreateAccountReviewPageProps = {
  searchParams: Promise<{
    accountKey?: string;
  }>;
};

export default async function CreateAccountReviewPage({
  searchParams,
}: CreateAccountReviewPageProps) {
  const { accountKey } = await searchParams;

  if (!accountKey) {
    redirect(getCreateBasicInfoPath());
  }

  const account = await loadDraftAccountByKey(accountKey);

  if (!account) {
    redirect(getCreateBasicInfoPath());
  }

  return <AccountReviewScreen mode="create" account={account} />;
}
