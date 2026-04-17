import { redirect } from 'next/navigation';
import { loadAccountReviewByKey } from '@/features/accounts/account-loaders';
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

  const review = await loadAccountReviewByKey(accountKey);

  if (!review) {
    redirect(getCreateBasicInfoPath());
  }

  return <AccountReviewScreen mode="create" review={review} />;
}
