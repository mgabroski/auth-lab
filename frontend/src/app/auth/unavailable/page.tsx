/**
 * frontend/src/app/auth/unavailable/page.tsx
 *
 * WHY:
 * - Dedicated route for unknown/inactive tenant bootstrap state.
 * - Mirrors backend anti-enumeration posture by rendering the same generic unavailable view.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { getRouteStateRedirectPath, TOPOLOGY_CHECK_PATH } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function TenantUnavailablePage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Tenant Unavailable</h1>
        <p>The tenant unavailable page could not complete bootstrap.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
        <p>
          Use <Link href={TOPOLOGY_CHECK_PATH}>Topology Check</Link> to verify the foundation.
        </p>
      </main>
    );
  }

  if (bootstrap.routeState.kind !== 'TENANT_UNAVAILABLE') {
    redirect(getRouteStateRedirectPath(bootstrap.routeState));
  }

  return (
    <main>
      <h1>Hubins</h1>
      <p>This tenant is unavailable.</p>
      <p>
        The backend returns the same public bootstrap shape for unknown and inactive tenants, and
        this route intentionally preserves that behavior.
      </p>
    </main>
  );
}
