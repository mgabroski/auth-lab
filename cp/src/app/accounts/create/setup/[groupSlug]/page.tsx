import { notFound } from 'next/navigation';
import { loadCreateAccountDraft } from '@/features/accounts/mock-data';
import { AccountSetupGroupScreen } from '@/features/accounts/screens/account-setup-group-screen';
import { getSetupGroupBySlug } from '@/features/accounts/setup-groups';

type CreateSetupGroupPageProps = {
  params: Promise<{
    groupSlug: string;
  }>;
};

export default async function CreateSetupGroupPage({ params }: CreateSetupGroupPageProps) {
  const { groupSlug } = await params;
  const group = getSetupGroupBySlug(groupSlug);

  if (!group) {
    notFound();
  }

  const account = await loadCreateAccountDraft();

  if (!account) {
    notFound();
  }

  return <AccountSetupGroupScreen mode="create" account={account} group={group} />;
}
