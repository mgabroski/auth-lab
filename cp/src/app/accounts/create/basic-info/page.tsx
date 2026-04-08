import { loadCreateAccountDraft } from '@/features/accounts/mock-data';
import { AccountBasicInfoScreen } from '@/features/accounts/screens/account-basic-info-screen';

export default async function CreateAccountBasicInfoPage() {
  const account = await loadCreateAccountDraft();

  return <AccountBasicInfoScreen mode="create" account={account} />;
}
