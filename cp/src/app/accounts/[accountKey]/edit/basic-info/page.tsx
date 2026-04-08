import { redirect } from 'next/navigation';
import { getEditSetupPath } from '@/shared/cp/links';

type EditAccountBasicInfoPageProps = {
  params: Promise<{
    accountKey: string;
  }>;
};

export default async function EditAccountBasicInfoPage({ params }: EditAccountBasicInfoPageProps) {
  const { accountKey } = await params;

  // WHY: the locked CP edit flow must re-enter at Step 2 (Account Setup), not Step 1.
  // Existing accounts are editable through setup/review only.
  // Basic Account Info is not a valid edit surface in this phase.
  redirect(getEditSetupPath(accountKey));
}
