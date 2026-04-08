import { notFound } from 'next/navigation';
import { loadEditableAccount } from '@/features/accounts/mock-data';
import { AccountBasicInfoScreen } from '@/features/accounts/screens/account-basic-info-screen';

type EditAccountBasicInfoPageProps = {
  params: Promise<{
    accountKey: string;
  }>;
};

export default async function EditAccountBasicInfoPage({ params }: EditAccountBasicInfoPageProps) {
  const { accountKey } = await params;
  const account = await loadEditableAccount(accountKey);

  if (!account) {
    notFound();
  }

  return <AccountBasicInfoScreen mode="edit" account={account} />;
}
