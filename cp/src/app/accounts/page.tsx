import { AccountsListScreen } from '@/features/accounts/screens/accounts-list-screen';
import { loadAccountsList } from '@/features/accounts/mock-data';

export default async function AccountsPage() {
  const accounts = await loadAccountsList();

  return <AccountsListScreen accounts={accounts} />;
}
