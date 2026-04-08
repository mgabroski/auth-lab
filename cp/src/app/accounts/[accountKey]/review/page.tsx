import { notFound } from 'next/navigation';
import { loadEditableAccount } from '@/features/accounts/mock-data';
import { AccountReviewScreen } from '@/features/accounts/screens/account-review-screen';

type EditAccountReviewPageProps = {
  params: Promise<{
    accountKey: string;
  }>;
};

export default async function EditAccountReviewPage({ params }: EditAccountReviewPageProps) {
  const { accountKey } = await params;
  const account = await loadEditableAccount(accountKey);

  if (!account) {
    notFound();
  }

  return <AccountReviewScreen mode="edit" account={account} />;
}
