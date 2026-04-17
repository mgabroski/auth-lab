import { notFound } from 'next/navigation';
import { loadEditableAccount } from '@/features/accounts/account-loaders';
import { AccountSetupGroupScreen } from '@/features/accounts/screens/account-setup-group-screen';
import { getSetupGroupBySlug } from '@/features/accounts/setup-groups';

type EditSetupGroupPageProps = {
  params: Promise<{
    accountKey: string;
    groupSlug: string;
  }>;
};

export default async function EditSetupGroupPage({ params }: EditSetupGroupPageProps) {
  const { accountKey, groupSlug } = await params;
  const account = await loadEditableAccount(accountKey);
  const group = getSetupGroupBySlug(groupSlug);

  if (!account || !group) {
    notFound();
  }

  return <AccountSetupGroupScreen mode="edit" account={account} group={group} />;
}
