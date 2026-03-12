/**
 * frontend/src/app/page.tsx
 *
 * WHY:
 * - This is now the real SSR auth/bootstrap gate for the application root.
 * - It resolves current tenant availability + session/continuation state from
 *   backend truth before any client hydration.
 *
 * RULES:
 * - Server Component only — no 'use client'.
 * - Root routing decisions must come from `/auth/config` + `/auth/me`.
 * - Do not duplicate continuation logic here; use shared route-state helpers.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { getRouteStateRedirectPath, TOPOLOGY_CHECK_PATH } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function RootPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    const errorMessage = bootstrap.error.message || 'Unknown bootstrap error';

    return (
      <main>
        <h1>Hubins</h1>
        <p>Frontend bootstrap failed before the root gate could resolve user state.</p>
        <p>
          <strong>Error:</strong> {errorMessage}
        </p>
        <p>
          Check backend/frontend wiring, then verify the foundation through{' '}
          <Link href={TOPOLOGY_CHECK_PATH}>Topology Check</Link>.
        </p>
      </main>
    );
  }

  redirect(getRouteStateRedirectPath(bootstrap.routeState));
}
