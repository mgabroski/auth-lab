/**
 * frontend/src/app/auth/page.tsx
 *
 * WHY:
 * - Provides the public auth entry target for the new root gate.
 * - Intentionally remains a minimal Phase 1 placeholder, not the final auth UI.
 *
 * RULES:
 * - Server Component only.
 * - Redirects away when backend truth says the user belongs in continuation or app flow.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import {
  getRouteStateRedirectPath,
  TOPOLOGY_CHECK_PATH,
  AUTH_TENANT_UNAVAILABLE_PATH,
} from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function AuthEntryPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Auth Entry</h1>
        <p>Bootstrap failed while loading the public auth entry route.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
        <p>
          Use <Link href={TOPOLOGY_CHECK_PATH}>Topology Check</Link> to verify SSR wiring.
        </p>
      </main>
    );
  }

  if (bootstrap.routeState.kind === 'TENANT_UNAVAILABLE') {
    redirect(AUTH_TENANT_UNAVAILABLE_PATH);
  }

  if (bootstrap.routeState.kind !== 'PUBLIC_ENTRY') {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  const { tenant } = bootstrap.config;

  return (
    <main>
      <h1>Hubins — Auth Entry</h1>
      <p>This route now represents the public auth/bootstrap entry for the current tenant.</p>

      <h2>Resolved tenant</h2>
      <pre>{JSON.stringify(tenant, null, 2)}</pre>

      <h2>Phase status</h2>
      <p>
        Phase 1 is complete when the root gate lands here for unauthenticated users and the resolved
        tenant configuration matches backend truth.
      </p>
      <p>Real login/signup/reset/invite screens will replace this placeholder in the next phase.</p>
    </main>
  );
}
