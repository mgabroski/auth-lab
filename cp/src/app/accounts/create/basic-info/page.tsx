/**
 * cp/src/app/accounts/create/basic-info/page.tsx
 *
 * CP Phase 2: renders the real Step 1 create form.
 *
 * WHY this is now a thin server page:
 * - The AccountBasicInfoScreen is a Client Component that manages its own form
 *   state. No server-side data pre-loading is needed for a blank create form.
 * - Phase 1 loaded a placeholder draft; Phase 2 starts with an empty form and
 *   submits via POST /api/cp/accounts on continue.
 */

import { AccountBasicInfoScreen } from '@/features/accounts/screens/account-basic-info-screen';

export default function CreateAccountBasicInfoPage() {
  return <AccountBasicInfoScreen />;
}
