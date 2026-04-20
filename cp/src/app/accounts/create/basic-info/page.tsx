/**
 * cp/src/app/accounts/create/basic-info/page.tsx
 *
 * WHY this is a thin server page:
 * - AccountBasicInfoScreen is a Client Component that manages its own form state.
 * - No server-side data pre-loading is needed for a blank create form.
 * - The page starts with an empty form and submits through POST /api/cp/accounts on continue.
 */

import React from 'react';
import { AccountBasicInfoScreen } from '@/features/accounts/screens/account-basic-info-screen';

export default function CreateAccountBasicInfoPage() {
  return <AccountBasicInfoScreen />;
}
