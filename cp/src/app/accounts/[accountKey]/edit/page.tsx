import { redirect } from 'next/navigation';
import { getEditSetupPath } from '@/shared/cp/links';

type EditAccountRedirectPageProps = {
  params: Promise<{
    accountKey: string;
  }>;
};

export default async function EditAccountRedirectPage({ params }: EditAccountRedirectPageProps) {
  const { accountKey } = await params;

  // WHY: the locked CP edit flow re-enters at Step 2 (Account Setup), not Step 1.
  // Step 1 identity fields (name and key) are immutable after account creation.
  // Operators editing an existing account go directly to the group configuration surface.
  redirect(getEditSetupPath(accountKey));
}
