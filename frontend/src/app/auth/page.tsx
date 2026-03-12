/**
 * frontend/src/app/auth/page.tsx
 *
 * WHY:
 * - Keeps `/auth` as a stable auth entry route while the real public forms now
 *   live on explicit child routes.
 * - Preserves the Phase 1/2 SSR bootstrap gate behavior, but redirects PUBLIC_ENTRY
 *   traffic to the real login screen.
 *
 * RULES:
 * - Server Component only.
 * - Routing decisions must still come from backend truth via loadAuthBootstrap().
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import {
  AUTH_LOGIN_PATH,
  TOPOLOGY_CHECK_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function AuthEntryPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Auth</h1>
        <p>The auth entry route could not load backend bootstrap truth.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
        <p>Verify wiring with the Topology Check page: {TOPOLOGY_CHECK_PATH}</p>
      </main>
    );
  }

  if (bootstrap.routeState.kind === 'PUBLIC_ENTRY') {
    redirect(AUTH_LOGIN_PATH);
  }

  redirect(getRouteStateRedirectPath(bootstrap.routeState));
}
