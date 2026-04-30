import { redirect } from 'next/navigation';
import { getCreateFlowEntryPath } from '@/shared/cp/links';

// WHY:
// - The canonical CP host entry is the app root.
// - The current no-auth CP phase must land operators directly on Step 1.
// - Keep this runtime-evaluated so Docker/CI cannot accidentally bake a stale 404.
export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default function ControlPlaneHomePage() {
  redirect(getCreateFlowEntryPath());
}
