/**
 * frontend/src/app/app/page.tsx
 *
 * WHY:
 * - Minimal but real authenticated workspace landing route for non-admin sessions.
 * - Only renders when backend bootstrap truth resolves to a fully-authenticated
 *   AGENT or USER session.
 * - AGENT and USER share this shell today, but future operational modules must
 *   use backend-resolved access to distinguish Agent operational scope from User
 *   own/self-service behavior.
 */

import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import { getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

export default async function WorkspaceAppPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Workspace</h1>
        <p>Bootstrap failed while loading the authenticated workspace route.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
      </main>
    );
  }

  const routeState = bootstrap.routeState;

  if (routeState.kind !== 'AUTHENTICATED_WORKSPACE') {
    redirect(getRouteStateRedirectPath(routeState));
  }

  return (
    <AuthenticatedShell
      eyebrow="Hubins workspace"
      title="Workspace"
      subtitle={
        'Authenticated workspace shell for User and Agent sessions. Agent and User share this shell ' +
        'while operational modules are still deferred.'
      }
      me={routeState.me}
    >
      <div style={{ display: 'grid', gap: '12px' }}>
        <h2 style={{ margin: 0, fontSize: '22px', lineHeight: 1.2 }}>
          Authenticated handoff complete
        </h2>
        <p style={{ margin: 0, fontSize: '15px', lineHeight: 1.7, color: '#475569' }}>
          The backend has already resolved tenant, session, continuation, and role truth for this
          workspace session. This shared shell does not make Agent and User behavior the same;
          future operational modules must use backend-resolved access before showing scoped data or
          actions.
        </p>
      </div>
    </AuthenticatedShell>
  );
}
