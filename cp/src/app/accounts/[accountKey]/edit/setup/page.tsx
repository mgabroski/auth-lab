import { notFound } from 'next/navigation';
import { loadEditableAccount } from '@/features/accounts/mock-data';
import { AccountSetupOverviewScreen } from '@/features/accounts/screens/account-setup-overview-screen';

type EditAccountSetupPageProps = {
  params: Promise<{
    accountKey: string;
  }>;
};

export default async function EditAccountSetupPage({ params }: EditAccountSetupPageProps) {
  const { accountKey } = await params;
  const account = await loadEditableAccount(accountKey);

  if (!account) {
    notFound();
  }

  return <AccountSetupOverviewScreen mode="edit" account={account} />;
}
