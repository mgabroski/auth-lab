/**
 * frontend/src/app/app/page.tsx
 *
 * WHY:
 * - Minimal but real authenticated landing route for workspace members.
 * - Only renders when backend bootstrap truth resolves to a fully-authenticated MEMBER session.
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import { getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function MemberAppPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Member app</h1>
        <p>Bootstrap failed while loading the member landing route.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
      </main>
    );
  }

  const routeState = bootstrap.routeState;

  if (routeState.kind !== 'AUTHENTICATED_MEMBER') {
    redirect(getRouteStateRedirectPath(routeState));
  }

  return (
    <AuthenticatedShell
      eyebrow="Hubins member workspace"
      title="Member app"
      subtitle="This is the minimal authenticated landing page for non-admin members after the root bootstrap gate and any required continuation are complete."
      me={routeState.me}
    >
      <div style={{ display: 'grid', gap: '12px' }}>
        <h2 style={{ margin: 0, fontSize: '22px', lineHeight: 1.2 }}>
          Authenticated handoff complete
        </h2>
        <p style={{ margin: 0, fontSize: '15px', lineHeight: 1.7, color: '#475569' }}>
          The backend has already resolved tenant, session, and continuation truth for this member
          session. This page is intentionally minimal for Phase 6 so the frontend lands on a real,
          protected route without starting unrelated product modules yet.
        </p>
      </div>
    </AuthenticatedShell>
  );
}
