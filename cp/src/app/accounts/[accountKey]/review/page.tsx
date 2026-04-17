import { notFound } from 'next/navigation';
import { loadAccountReviewByKey } from '@/features/accounts/account-loaders';
import { AccountReviewScreen } from '@/features/accounts/screens/account-review-screen';

type EditAccountReviewPageProps = {
  params: Promise<{
    accountKey: string;
  }>;
};

export default async function EditAccountReviewPage({ params }: EditAccountReviewPageProps) {
  const { accountKey } = await params;
  const review = await loadAccountReviewByKey(accountKey);

  if (!review) {
    notFound();
  }

  return <AccountReviewScreen mode="edit" review={review} />;
}
