import React from 'react';
import { redirect } from 'next/navigation';
import { loadDraftAccountByKey } from '@/features/accounts/account-loaders';
import { AccountSetupOverviewScreen } from '@/features/accounts/screens/account-setup-overview-screen';
import { getCreateBasicInfoPath } from '@/shared/cp/links';

type CreateAccountSetupPageProps = {
  searchParams: Promise<{
    accountKey?: string;
  }>;
};

export default async function CreateAccountSetupPage({
  searchParams,
}: CreateAccountSetupPageProps) {
  const { accountKey } = await searchParams;

  if (!accountKey) {
    redirect(getCreateBasicInfoPath());
  }

  const account = await loadDraftAccountByKey(accountKey);

  if (!account) {
    redirect(getCreateBasicInfoPath());
  }

  return <AccountSetupOverviewScreen mode="create" account={account} />;
}
