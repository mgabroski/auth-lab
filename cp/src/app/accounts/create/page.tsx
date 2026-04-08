import { redirect } from 'next/navigation';
import { getCreateFlowEntryPath } from '@/shared/cp/links';

export default function CreateAccountRedirectPage() {
  redirect(getCreateFlowEntryPath());
}
