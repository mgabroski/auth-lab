import { redirect } from 'next/navigation';
import { loadDraftAccountByKey } from '@/features/accounts/account-loaders';
import { AccountPersonalConfigScreen } from '@/features/accounts/screens/account-personal-config-screen';
import { getCreateBasicInfoPath } from '@/shared/cp/links';

type CreatePersonalSetupPageProps = {
  searchParams: Promise<{
    accountKey?: string;
  }>;
};

export default async function CreatePersonalSetupPage({
  searchParams,
}: CreatePersonalSetupPageProps) {
  const { accountKey } = await searchParams;

  if (!accountKey) {
    redirect(getCreateBasicInfoPath());
  }

  const account = await loadDraftAccountByKey(accountKey);

  if (!account) {
    redirect(getCreateBasicInfoPath());
  }

  return <AccountPersonalConfigScreen mode="create" account={account} />;
}
