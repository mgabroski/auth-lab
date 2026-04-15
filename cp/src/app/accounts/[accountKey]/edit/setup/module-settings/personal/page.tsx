import { notFound } from 'next/navigation';
import { loadEditableAccount } from '@/features/accounts/mock-data';
import { AccountPersonalConfigScreen } from '@/features/accounts/screens/account-personal-config-screen';

type EditPersonalSetupPageProps = {
  params: Promise<{
    accountKey: string;
  }>;
};

export default async function EditPersonalSetupPage({ params }: EditPersonalSetupPageProps) {
  const { accountKey } = await params;
  const account = await loadEditableAccount(accountKey);

  if (!account) {
    notFound();
  }

  return <AccountPersonalConfigScreen mode="edit" account={account} />;
}
