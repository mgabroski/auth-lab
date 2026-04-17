import { notFound, redirect } from 'next/navigation';
import { loadDraftAccountByKey } from '@/features/accounts/account-loaders';
import { AccountSetupGroupScreen } from '@/features/accounts/screens/account-setup-group-screen';
import { getSetupGroupBySlug } from '@/features/accounts/setup-groups';
import { getCreateBasicInfoPath } from '@/shared/cp/links';

type CreateSetupGroupPageProps = {
  params: Promise<{
    groupSlug: string;
  }>;
  searchParams: Promise<{
    accountKey?: string;
  }>;
};

export default async function CreateSetupGroupPage({
  params,
  searchParams,
}: CreateSetupGroupPageProps) {
  const { groupSlug } = await params;
  const { accountKey } = await searchParams;
  const group = getSetupGroupBySlug(groupSlug);

  if (!group) {
    notFound();
  }

  if (!accountKey) {
    redirect(getCreateBasicInfoPath());
  }

  const account = await loadDraftAccountByKey(accountKey);

  if (!account) {
    redirect(getCreateBasicInfoPath());
  }

  return <AccountSetupGroupScreen mode="create" account={account} group={group} />;
}
