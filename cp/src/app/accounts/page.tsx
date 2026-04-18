/**
 * cp/src/app/accounts/page.tsx
 *
 * WHY:
 * - Server entry for the CP accounts list.
 * - Reads the real backend-backed accounts list and passes real Step 2 progress
 *   into the list screen.
 */

import React from 'react';
import { AccountsListScreen } from '@/features/accounts/screens/accounts-list-screen';
import { loadAccountsList } from '@/features/accounts/account-loaders';

export default async function AccountsPage() {
  const accounts = await loadAccountsList();

  return <AccountsListScreen accounts={accounts} />;
}
