import { notFound } from 'next/navigation';
import { loadCreateAccountDraft } from '@/features/accounts/mock-data';
import { AccountSetupOverviewScreen } from '@/features/accounts/screens/account-setup-overview-screen';

export default async function CreateAccountSetupPage() {
  const account = await loadCreateAccountDraft();

  if (!account) {
    notFound();
  }

  return <AccountSetupOverviewScreen mode="create" account={account} />;
}
