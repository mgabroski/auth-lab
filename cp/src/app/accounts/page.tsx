/**
 * cp/src/app/accounts/page.tsx
 *
 * CP Phase 2: accounts list now reads real backend data via loadAccountsList().
 * loadAccountsList() calls GET /cp/accounts and adapts the response to the
 * Phase 1 screen shape (name / key / setupGroupsReviewed).
 */

import { AccountsListScreen } from '@/features/accounts/screens/accounts-list-screen';
import { loadAccountsList } from '@/features/accounts/mock-data';

export default async function AccountsPage() {
  const accounts = await loadAccountsList();

  return <AccountsListScreen accounts={accounts} />;
}
