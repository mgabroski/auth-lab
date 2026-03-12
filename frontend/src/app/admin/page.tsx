/**
 * frontend/src/app/admin/page.tsx
 *
 * WHY:
 * - Minimal but real authenticated landing route for workspace admins.
 * - Only renders when backend bootstrap truth resolves to a fully-authenticated ADMIN session.
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import { getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function AdminPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Admin</h1>
        <p>Bootstrap failed while loading the admin landing route.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
      </main>
    );
  }

  const routeState = bootstrap.routeState;

  if (routeState.kind !== 'AUTHENTICATED_ADMIN') {
    redirect(getRouteStateRedirectPath(routeState));
  }

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Admin dashboard"
      subtitle="This is the minimal authenticated landing page for workspace admins after the root bootstrap gate and any required continuation are complete."
      me={routeState.me}
    >
      <div style={{ display: 'grid', gap: '12px' }}>
        <h2 style={{ margin: 0, fontSize: '22px', lineHeight: 1.2 }}>Admin landing ready</h2>
        <p style={{ margin: 0, fontSize: '15px', lineHeight: 1.7, color: '#475569' }}>
          Admin users are separated from members at the route-state layer so the root gate lands
          them in <code>/admin</code> instead of the member app. This page stays intentionally
          minimal in Phase 6 while still using the real backend session and logout flow.
        </p>
      </div>
    </AuthenticatedShell>
  );
}
