import { notFound } from 'next/navigation';
import { loadCreateAccountDraft } from '@/features/accounts/mock-data';
import { AccountReviewScreen } from '@/features/accounts/screens/account-review-screen';

export default async function CreateAccountReviewPage() {
  const account = await loadCreateAccountDraft();

  if (!account) {
    notFound();
  }

  return <AccountReviewScreen mode="create" account={account} />;
}
