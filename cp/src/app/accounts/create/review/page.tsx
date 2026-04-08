import { loadCreateAccountDraft } from '@/features/accounts/mock-data';
import { AccountReviewScreen } from '@/features/accounts/screens/account-review-screen';

export default async function CreateAccountReviewPage() {
  const account = await loadCreateAccountDraft();

  return <AccountReviewScreen mode="create" account={account} />;
}
