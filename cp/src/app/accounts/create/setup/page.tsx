import { loadCreateAccountDraft } from '@/features/accounts/mock-data';
import { AccountSetupOverviewScreen } from '@/features/accounts/screens/account-setup-overview-screen';

export default async function CreateAccountSetupPage() {
  const account = await loadCreateAccountDraft();

  return <AccountSetupOverviewScreen mode="create" account={account} />;
}
