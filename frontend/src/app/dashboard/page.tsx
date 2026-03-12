/**
 * frontend/src/app/dashboard/page.tsx
 *
 * WHY:
 * - Minimal authenticated landing route for the new root gate.
 * - Matches the backend/docs use of `/dashboard` as the safe post-auth in-app target.
 *
 * RULES:
 * - Server Component only.
 * - Redirects away unless backend truth says the session is fully continued.
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function DashboardPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Dashboard</h1>
        <p>Bootstrap failed while loading the authenticated entry route.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
      </main>
    );
  }

  if (bootstrap.routeState.kind !== 'AUTHENTICATED_APP') {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  const authenticatedState = bootstrap.routeState;

  return (
    <main>
      <h1>Hubins — Dashboard</h1>
      <p>This is the Phase 1 authenticated entry placeholder.</p>

      <h2>User</h2>
      <pre>{JSON.stringify(authenticatedState.me.user, null, 2)}</pre>

      <h2>Membership</h2>
      <pre>{JSON.stringify(authenticatedState.me.membership, null, 2)}</pre>

      <h2>Tenant</h2>
      <pre>{JSON.stringify(authenticatedState.me.tenant, null, 2)}</pre>
    </main>
  );
}
