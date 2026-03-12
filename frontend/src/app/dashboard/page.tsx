/**
 * frontend/src/app/dashboard/page.tsx
 *
 * WHY:
 * - Preserves `/dashboard` as a compatibility route for older links and returnTo values.
 * - Hands off to the correct current landing route (`/app` or `/admin`) using backend truth.
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
        <h1>Hubins — Dashboard handoff</h1>
        <p>Bootstrap failed while loading the legacy dashboard compatibility route.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
      </main>
    );
  }

  redirect(getRouteStateRedirectPath(bootstrap.routeState));
}
